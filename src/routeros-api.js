import net from 'node:net';
import tls from 'node:tls';
import { isIP } from 'node:net';

const MAX_WORD_BYTES = 1024 * 1024;
const MAX_BUFFER_BYTES = 8 * 1024 * 1024;

export class RouterOsApiError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'RouterOsApiError';
    this.details = details;
  }
}

function encodeLength(length) {
  if (!Number.isSafeInteger(length) || length < 0 || length > 0xffffffff) {
    throw new RangeError('RouterOS API word length is out of range');
  }
  if (length < 0x80) return Buffer.from([length]);
  if (length < 0x4000) {
    const n = length | 0x8000;
    return Buffer.from([(n >> 8) & 0xff, n & 0xff]);
  }
  if (length < 0x200000) {
    const n = length | 0xc00000;
    return Buffer.from([(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
  }
  if (length < 0x10000000) {
    const n = (length | 0xe0000000) >>> 0;
    const result = Buffer.allocUnsafe(4);
    result.writeUInt32BE(n, 0);
    return result;
  }
  return Buffer.concat([Buffer.from([0xf0]), Buffer.from([
    (length >>> 24) & 0xff,
    (length >>> 16) & 0xff,
    (length >>> 8) & 0xff,
    length & 0xff,
  ])]);
}

export function encodeWord(value) {
  const bytes = Buffer.from(String(value), 'utf8');
  if (bytes.length > MAX_WORD_BYTES) throw new RangeError('RouterOS API word is too large');
  return Buffer.concat([encodeLength(bytes.length), bytes]);
}

export function encodeSentence(words) {
  return Buffer.concat([...words.map(encodeWord), Buffer.from([0])]);
}

function readLength(buffer, offset) {
  if (offset >= buffer.length) return null;
  const first = buffer[offset];
  if (first < 0x80) return { length: first, bytes: 1 };
  if (first < 0xc0) {
    if (buffer.length < offset + 2) return null;
    return { length: ((first & 0x7f) << 8) | buffer[offset + 1], bytes: 2 };
  }
  if (first < 0xe0) {
    if (buffer.length < offset + 3) return null;
    return {
      length: ((first & 0x3f) << 16) | (buffer[offset + 1] << 8) | buffer[offset + 2],
      bytes: 3,
    };
  }
  if (first < 0xf0) {
    if (buffer.length < offset + 4) return null;
    return {
      length: ((first & 0x1f) * 0x1000000) + (buffer[offset + 1] << 16) + (buffer[offset + 2] << 8) + buffer[offset + 3],
      bytes: 4,
    };
  }
  if (first < 0xf8) {
    if (buffer.length < offset + 5) return null;
    return {
      length: buffer.readUInt32BE(offset + 1),
      bytes: 5,
    };
  }
  throw new RouterOsApiError(`Unsupported RouterOS API control byte 0x${first.toString(16)}`);
}

/** Decode one complete sentence, or return null if the buffer ends mid-sentence. */
export function decodeSentence(buffer) {
  const words = [];
  let offset = 0;
  while (offset < buffer.length) {
    const field = readLength(buffer, offset);
    if (field === null) return null;
    offset += field.bytes;
    if (field.length === 0) return { words, bytesRead: offset };
    if (field.length > MAX_WORD_BYTES) {
      throw new RouterOsApiError('RouterOS API response contains an oversized word');
    }
    if (buffer.length < offset + field.length) return null;
    words.push(buffer.subarray(offset, offset + field.length).toString('utf8'));
    offset += field.length;
  }
  return null;
}

export function parseAttributes(words) {
  const attributes = {};
  for (const word of words) {
    if (!word.startsWith('=')) continue;
    const separator = word.indexOf('=', 1);
    if (separator < 0) continue;
    attributes[word.slice(1, separator)] = word.slice(separator + 1);
  }
  return attributes;
}

function validateHost(host) {
  if (typeof host !== 'string' || host.length === 0 || host.length > 253) {
    throw new TypeError('A valid RouterOS hostname or IP address is required');
  }
  if (isIP(host)) return;
  const hostname = host.endsWith('.') ? host.slice(0, -1) : host;
  const labels = hostname.split('.');
  const valid = labels.every((label) => label.length > 0 && label.length <= 63
    && /^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label));
  if (!valid) throw new TypeError('RouterOS host must be an IP address or a DNS hostname');
}

export class RouterOsApiClient {
  constructor({ host, port = 8729, username, password, tls: useTls = true, tlsCa, tlsRejectUnauthorized = true, timeoutMs = 8000 }) {
    validateHost(host);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new TypeError('Invalid RouterOS API port');
    if (!username || typeof username !== 'string') throw new TypeError('RouterOS username is required');
    if (typeof password !== 'string') throw new TypeError('RouterOS password must be provided as a string');
    this.config = { host, port, username, password, useTls, tlsCa, tlsRejectUnauthorized, timeoutMs };
    this.socket = null;
    this.buffer = Buffer.alloc(0);
    this.sentences = [];
    this.waiters = [];
    this.terminalError = null;
    this.closing = false;
    this.commandTail = Promise.resolve();
  }

  async connect() {
    if (this.socket) return;
    const { host, port, useTls, tlsCa, tlsRejectUnauthorized, timeoutMs } = this.config;
    const socket = useTls
      ? tls.connect({
        host,
        port,
        ...(isIP(host) ? {} : { servername: host }),
        rejectUnauthorized: tlsRejectUnauthorized,
        ...(tlsCa ? { ca: tlsCa } : {}),
      })
      : net.createConnection({ host, port });
    this.socket = socket;
    socket.on('data', (chunk) => this.#onData(chunk));
    socket.on('error', (error) => this.#fail(new RouterOsApiError(`RouterOS API connection failed: ${error.message}`)));
    socket.setTimeout(timeoutMs, () => socket.destroy(new RouterOsApiError(`Timed out waiting for a RouterOS API reply after ${timeoutMs} ms`)));
    socket.on('close', () => {
      if (!this.closing) this.#fail(new RouterOsApiError('RouterOS API connection closed unexpectedly'));
    });

    await new Promise((resolve, reject) => {
      let settled = false;
      const readyEvent = useTls ? 'secureConnect' : 'connect';
      const finish = (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error);
        else resolve();
      };
      const timer = setTimeout(() => {
        const error = new RouterOsApiError(`Timed out connecting to RouterOS at ${host}:${port}`);
        socket.destroy(error);
        finish(error);
      }, timeoutMs);
      socket.once(readyEvent, () => finish());
      socket.once('error', (error) => finish(new RouterOsApiError(`RouterOS API connection failed: ${error.message}`)));
    });

    try {
      const replies = await this.#exchange([
        '/login',
        `=name=${this.config.username}`,
        `=password=${this.config.password}`,
      ]);
      if (replies.error) throw new RouterOsApiError(`RouterOS authentication failed: ${replies.error}`);
    } catch (error) {
      await this.close();
      throw error;
    }
  }

  async print(path, properties, queryWords = []) {
    const commandPath = path.startsWith('/') ? path : `/${path}`;
    const attributes = { '.proplist': properties.join(',') };
    return this.command(`${commandPath}/print`, attributes, queryWords);
  }

  async printAll(path, queryWords = []) {
    const commandPath = path.startsWith('/') ? path : `/${path}`;
    return this.command(`${commandPath}/print`, {}, queryWords);
  }

  async command(commandPath, attributes = {}, queryWords = []) {
    const operation = async () => {
      if (!this.socket || this.terminalError) throw this.terminalError ?? new RouterOsApiError('RouterOS API client is not connected');
      const words = [commandPath];
      for (const [key, value] of Object.entries(attributes)) words.push(`=${key}=${value}`);
      words.push(...queryWords);
      const response = await this.#exchange(words);
      if (response.error) throw new RouterOsApiError(`RouterOS rejected the command: ${response.error}`, response.attributes);
      return response.rows;
    };
    const result = this.commandTail.then(operation, operation);
    this.commandTail = result.then(() => undefined, () => undefined);
    return result;
  }

  async #exchange(words) {
    const socket = this.socket;
    if (!socket || socket.destroyed) throw this.terminalError ?? new RouterOsApiError('RouterOS API socket is not connected');
    await new Promise((resolve, reject) => {
      socket.write(encodeSentence(words), (error) => error ? reject(error) : resolve());
    });
    const rows = [];
    let commandError = null;
    let lastAttributes = {};
    while (true) {
      const sentence = await this.#nextSentence();
      const type = sentence[0];
      const attributes = parseAttributes(sentence.slice(1));
      lastAttributes = attributes;
      if (type === '!re') rows.push(attributes);
      else if (type === '!trap') commandError = attributes.message ?? attributes.category ?? 'unknown RouterOS error';
      else if (type === '!fatal') throw new RouterOsApiError(`RouterOS reported a fatal error: ${attributes.message ?? 'connection failure'}`);
      else if (type === '!empty') return { rows, attributes: lastAttributes, error: commandError };
      else if (type === '!done') return { rows, attributes: lastAttributes, error: commandError };
      else throw new RouterOsApiError(`Unexpected RouterOS API response: ${type ?? '(empty)'}`);
    }
  }

  #onData(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    if (this.buffer.length > MAX_BUFFER_BYTES) {
      this.#fail(new RouterOsApiError('RouterOS API response exceeded the size limit'));
      this.socket?.destroy();
      return;
    }
    try {
      while (this.buffer.length > 0) {
        const decoded = decodeSentence(this.buffer);
        if (!decoded) break;
        this.buffer = this.buffer.subarray(decoded.bytesRead);
        const waiter = this.waiters.shift();
        if (waiter) waiter.resolve(decoded.words);
        else this.sentences.push(decoded.words);
      }
    } catch (error) {
      this.#fail(error);
      this.socket?.destroy();
    }
  }

  #nextSentence() {
    if (this.sentences.length) return Promise.resolve(this.sentences.shift());
    if (this.terminalError) return Promise.reject(this.terminalError);
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
  }

  #fail(error) {
    if (this.terminalError) return;
    this.terminalError = error;
    for (const waiter of this.waiters.splice(0)) waiter.reject(error);
  }

  async close() {
    const socket = this.socket;
    if (!socket) return;
    this.closing = true;
    this.socket = null;
    await new Promise((resolve) => {
      const timer = setTimeout(() => {
        socket.destroy();
        resolve();
      }, 300);
      socket.once('close', () => {
        clearTimeout(timer);
        resolve();
      });
      socket.end();
    });
  }
}
