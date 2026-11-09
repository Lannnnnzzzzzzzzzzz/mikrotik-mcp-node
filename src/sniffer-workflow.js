import net from 'node:net';

const MAX_MANAGED_CAPTURE_SECONDS = 60;
const ORIGINAL_FIELDS = ['streaming-server', 'streaming-port', 'filter-stream'];

function strictBoolean(value, field) {
  if (value === true || value === 'true' || value === 'yes') return true;
  if (value === false || value === 'false' || value === 'no') return false;
  throw new Error(`RouterOS did not return a known ${field} state; refusing to alter the sniffer.`);
}

function wait(ms, waitFn) {
  return waitFn(ms);
}

/** Run a bounded local capture and RouterOS sniffer session with best-effort cleanup. */
export async function runRouterSnifferCapture({
  device,
  name,
  durationSeconds,
  bindAddress,
  port,
  withRouter,
  captureManager,
  waitFn = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now = () => Date.now(),
  keepAliveIntervalMs = 3000,
} = {}) {
  if (typeof device !== 'string' || !/^[A-Za-z0-9_-]{1,48}$/.test(device)) throw new TypeError('device must be a configured router ID.');
  if (typeof name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$/.test(name)) throw new TypeError('name must be a safe capture label.');
  if (!Number.isInteger(durationSeconds) || durationSeconds < 1 || durationSeconds > MAX_MANAGED_CAPTURE_SECONDS) {
    throw new RangeError(`durationSeconds must be from 1 to ${MAX_MANAGED_CAPTURE_SECONDS}.`);
  }
  if (typeof bindAddress !== 'string' || net.isIP(bindAddress) === 0 || bindAddress === '0.0.0.0' || bindAddress === '::' || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new TypeError('An explicit non-wildcard IP capture bind address and UDP port are required.');
  }
  if (typeof withRouter !== 'function' || !captureManager || typeof captureManager.start !== 'function' || typeof captureManager.stop !== 'function') {
    throw new TypeError('withRouter and a TZSP capture manager are required.');
  }
  if (typeof waitFn !== 'function' || typeof now !== 'function' || !Number.isInteger(keepAliveIntervalMs) || keepAliveIntervalMs < 100 || keepAliveIntervalMs > 7000) {
    throw new TypeError('Invalid wait or keepalive configuration.');
  }

  const capture = await captureManager.start({ device, name, durationSeconds });
  let remoteStarted = false;
  let remoteStateMayHaveChanged = false;
  const remoteCleanupErrors = [];
  let remoteOperationError = null;
  const startedAt = new Date(now()).toISOString();
  try {
    await withRouter(device, async (client) => {
      const rows = await client.print('/tool/sniffer', ['running', 'streaming-enabled', ...ORIGINAL_FIELDS]);
      if (rows.length !== 1) throw new Error('RouterOS sniffer state is missing or ambiguous; no remote settings were changed.');
      const before = rows[0];
      if (strictBoolean(before.running, 'running') || strictBoolean(before['streaming-enabled'], 'streaming-enabled')) {
        throw new Error('RouterOS sniffer or TZSP streaming is already active; stop it manually before starting a managed capture.');
      }
      if (ORIGINAL_FIELDS.some((field) => typeof before[field] !== 'string')) {
        throw new Error('RouterOS did not return all prior streaming settings; refusing to change the sniffer because they could not be restored exactly.');
      }
      const restore = Object.fromEntries(ORIGINAL_FIELDS.map((field) => [field, before[field]]));
      let settingsMayHaveChanged = false;
      try {
        settingsMayHaveChanged = true;
        remoteStateMayHaveChanged = true;
        await client.command('/tool/sniffer/set', {
          'streaming-enabled': 'yes',
          'streaming-server': bindAddress,
          'streaming-port': String(port),
          'filter-stream': 'yes',
        });
        await client.command('/tool/sniffer/start');
        remoteStarted = true;
        const deadline = now() + durationSeconds * 1000;
        while (now() < deadline) {
          const pause = Math.min(keepAliveIntervalMs, deadline - now());
          await wait(pause, waitFn);
          if (now() < deadline) await client.print('/system/resource', ['version']);
        }
      } finally {
        if (settingsMayHaveChanged) {
          try { await client.command('/tool/sniffer/stop'); }
          catch (error) { remoteCleanupErrors.push(`stop: ${error instanceof Error ? error.message : 'unknown error'}`); }
          try { await client.command('/tool/sniffer/set', restore); }
          catch (error) { remoteCleanupErrors.push(`restore settings: ${error instanceof Error ? error.message : 'unknown error'}`); }
        }
      }
    });
  } catch (error) {
    remoteOperationError = error instanceof Error ? error.message : 'unknown router operation error';
  }

  let finalizedCapture;
  let localFinalizeError = null;
  try {
    finalizedCapture = await captureManager.stop(capture.id);
  } catch (error) {
    localFinalizeError = error instanceof Error ? error.message : 'unknown error';
  }
  const result = {
    device,
    capture: finalizedCapture ?? capture,
    startedAt,
    durationSeconds,
    routerSnifferStarted: remoteStarted,
    routerCleanupAttempted: true,
    routerSettingsRestored: remoteCleanupErrors.length === 0,
  };
  if (remoteCleanupErrors.length) {
    throw new Error(`Managed capture ended with cleanup uncertainty. Local capture ID ${capture.id}; inspect RouterOS /tool/sniffer before retrying. ${remoteCleanupErrors.join('; ')}`);
  }
  if (localFinalizeError) throw new Error(`RouterOS sniffer cleanup completed, but the local PCAP could not be finalized (${localFinalizeError}). Capture ID ${capture.id}.`);
  if (remoteOperationError && remoteStateMayHaveChanged) {
    throw new Error(`Managed capture did not complete, but RouterOS stop and prior settings restoration succeeded. Local capture ID ${capture.id}. ${remoteOperationError}`);
  }
  if (remoteOperationError) throw new Error(`Managed capture could not start; RouterOS settings were not changed and the local receiver was stopped. ${remoteOperationError}`);
  return { ...result, note: 'The RouterOS sniffer was stopped and prior streaming settings were restored. Cleanup is best-effort if the MCP process, network, or router fails; keep captures short and verify router state after any interruption.' };
}

export { MAX_MANAGED_CAPTURE_SECONDS };
