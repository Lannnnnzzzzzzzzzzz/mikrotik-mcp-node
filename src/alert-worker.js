function toTimestamp(value) {
  if (value instanceof Date) return value.toISOString();
  if (typeof value === 'string') return value;
  return new Date(value).toISOString();
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

export function createAlertWorker({
  listDevices,
  listRules,
  collect,
  record,
  now = () => new Date(),
  setTimeoutFn = setTimeout,
  clearTimeoutFn = clearTimeout,
  minIntervalMs = 60000,
  maxIntervalMs = 86400000,
}) {
  for (const [name, fn] of Object.entries({ listDevices, listRules, collect, record, now, setTimeoutFn, clearTimeoutFn })) {
    if (typeof fn !== 'function') throw new TypeError(`${name} must be a function.`);
  }
  if (!Number.isFinite(minIntervalMs) || !Number.isFinite(maxIntervalMs) || minIntervalMs < 1 || maxIntervalMs < minIntervalMs) {
    throw new RangeError('Invalid alert worker interval bounds.');
  }

  let running = false;
  let intervalMs = null;
  let startedAt = null;
  let lastPollAt = null;
  let lastSuccessAt = null;
  let lastError = null;
  let pollCount = 0;
  let timer = null;
  let inFlight = null;

  function status() {
    return { running, intervalMs, startedAt, lastPollAt, lastSuccessAt, lastError, pollCount, inFlight: inFlight !== null };
  }

  function scheduleNext() {
    if (!running || timer !== null) return;
    timer = setTimeoutFn(() => {
      timer = null;
      if (!running) return;
      void runPoll().finally(scheduleNext);
    }, intervalMs);
  }

  function runPoll() {
    if (inFlight !== null) return inFlight;

    pollCount += 1;
    lastPollAt = toTimestamp(now());
    lastError = null;

    inFlight = (async () => {
      const failures = [];
      try {
        const devices = await listDevices();
        if (!Array.isArray(devices)) throw new TypeError('listDevices must return an array.');

        for (const device of devices) {
          try {
            const rules = await listRules(device);
            if (!Array.isArray(rules)) throw new TypeError('listRules must return an array.');
            const enabledRules = rules.filter((rule) => rule?.enabled === true);
            if (enabledRules.length === 0) continue;

            const values = await collect(device, enabledRules);
            await record(device, values);
          } catch (error) {
            const deviceId = device && typeof device === 'object' ? device.id : device;
            failures.push(`${deviceId ?? 'unknown device'}: ${errorMessage(error)}`);
          }
        }
      } catch (error) {
        failures.push(errorMessage(error));
      }

      if (failures.length) lastError = failures.join('; ');
      else lastSuccessAt = toTimestamp(now());
      return { success: failures.length === 0, errors: [...failures] };
    })();

    const activePoll = inFlight;
    return activePoll.finally(() => {
      if (inFlight === activePoll) inFlight = null;
    });
  }

  async function start(requestedIntervalMs) {
    if (running) throw new Error('Alert worker is already running.');
    if (!Number.isInteger(requestedIntervalMs) || requestedIntervalMs < minIntervalMs || requestedIntervalMs > maxIntervalMs) {
      throw new RangeError(`intervalMs must be an integer from ${minIntervalMs} to ${maxIntervalMs}.`);
    }

    running = true;
    intervalMs = requestedIntervalMs;
    startedAt = toTimestamp(now());
    lastError = null;

    await runPoll();
    if (running) scheduleNext();
    return status();
  }

  async function stop() {
    running = false;
    if (timer !== null) {
      clearTimeoutFn(timer);
      timer = null;
    }
    if (inFlight !== null) await inFlight;
    return status();
  }

  function pollOnce() {
    return runPoll();
  }

  return { start, stop, status, pollOnce };
}
