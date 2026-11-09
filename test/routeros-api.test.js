import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import {
  decodeSentence,
  encodeSentence,
  encodeWord,
  parseAttributes,
  RouterOsApiClient,
} from '../src/routeros-api.js';

function encodedLength(word) {
  const byte = word[0];
  if (byte < 0x80) return { value: byte, bytes: 1 };
  if (byte < 0xc0) return { value: ((byte & 0x7f) << 8) | word[1], bytes: 2 };
  if (byte < 0xe0) return { value: ((byte & 0x3f) << 16) | (word[1] << 8) | word[2], bytes: 3 };
  if (byte < 0xf0) return { value: ((byte & 0x1f) * 0x1000000) + (word[1] << 16) + (word[2] << 8) + word[3], bytes: 4 };
  return { value: word.readUInt32BE(1), bytes: 5 };
}

test('encodes RouterOS API word length prefixes across supported boundaries', () => {
  for (const length of [0, 1, 127, 128, 16383, 16384, 1048576]) {
    const encoded = encodeWord('x'.repeat(length));
    const decoded = encodedLength(encoded);
    assert.equal(decoded.value, length);
    assert.equal(encoded.length, decoded.bytes + length);
  }
});

test('encodes and decodes a multi-word sentence', () => {
  const sentence = ['/interface/print', '=.proplist=.id,name,running', '=name=ether1'];
  const decoded = decodeSentence(encodeSentence(sentence));
  assert.deepEqual(decoded.words, sentence);
  assert.equal(decoded.bytesRead, encodeSentence(sentence).length);
});

test('returns null for incomplete sentences', () => {
  assert.equal(decodeSentence(Buffer.from([0x05, 0x61, 0x62])), null);
  assert.equal(decodeSentence(Buffer.from([0x81])), null);
});

test('parses RouterOS key-value response words without truncating values', () => {
  assert.deepEqual(parseAttributes(['!re', '=name=ether1', '=comment=wan=primary', '=running=true']), {
    name: 'ether1',
    comment: 'wan=primary',
    running: 'true',
  });
});

test('performs login and a print request over a local mock RouterOS API peer', async (t) => {
  const received = [];
  const peer = net.createServer((socket) => {
    let buffer = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      while (true) {
        const decoded = decodeSentence(buffer);
        if (!decoded) break;
        buffer = buffer.subarray(decoded.bytesRead);
        received.push(decoded.words);
        if (decoded.words[0] === '/login') {
          socket.write(encodeSentence(['!done']));
        } else if (decoded.words[0] === '/system/identity/print') {
          socket.write(encodeSentence(['!re', '=name=Lab-Router']));
          socket.write(encodeSentence(['!done']));
        } else if (decoded.words[0] === '/ip/firewall/filter/print') {
          socket.write(encodeSentence(['!re', '=.id=*1', '=chain=input', '=action=drop', '=disabled=no', '=src-address=192.0.2.0/24', '=comment=private-comment']));
          socket.write(encodeSentence(['!done']));
        } else {
          socket.write(encodeSentence(['!trap', '=message=unexpected mock command']));
          socket.write(encodeSentence(['!done']));
        }
      }
    });
  });

  await new Promise((resolve) => peer.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => peer.close(resolve)));
  const { port } = peer.address();
  const client = new RouterOsApiClient({
    host: '127.0.0.1',
    port,
    username: 'test-user',
    password: 'test-password',
    tls: false,
    timeoutMs: 2000,
  });

  try {
    await client.connect();
    const identity = await client.print('/system/identity', ['name']);
      assert.deepEqual(identity, [{ name: 'Lab-Router' }]);
      const rules = await client.printAll('/ip/firewall/filter');
      assert.deepEqual(rules, [{ '.id': '*1', chain: 'input', action: 'drop', disabled: 'no', 'src-address': '192.0.2.0/24', comment: 'private-comment' }]);
  } finally {
    await client.close();
  }

  assert.deepEqual(received[0], ['/login', '=name=test-user', '=password=test-password']);
  assert.equal(received[1][0], '/system/identity/print');
      assert.deepEqual(received[1].slice(1), ['=.proplist=name']);
      assert.deepEqual(received[2], ['/ip/firewall/filter/print']);
});

test('serializes concurrent RouterOS commands so replies cannot be assigned to the wrong caller', async (t) => {
  const received = [];
  const peer = net.createServer((socket) => {
    let buffer = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      while (true) {
        const decoded = decodeSentence(buffer);
        if (!decoded) break;
        buffer = buffer.subarray(decoded.bytesRead);
        received.push(decoded.words[0]);
        if (decoded.words[0] === '/login') {
          socket.write(encodeSentence(['!done']));
        } else if (decoded.words[0] === '/first/print') {
          setTimeout(() => {
            socket.write(encodeSentence(['!re', '=name=first-result']));
            socket.write(encodeSentence(['!done']));
          }, 30);
        } else if (decoded.words[0] === '/second/print') {
          socket.write(encodeSentence(['!re', '=name=second-result']));
          socket.write(encodeSentence(['!done']));
        } else {
          socket.write(encodeSentence(['!trap', '=message=unexpected mock command']));
          socket.write(encodeSentence(['!done']));
        }
      }
    });
  });

  await new Promise((resolve) => peer.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => peer.close(resolve)));
  const { port } = peer.address();
  const client = new RouterOsApiClient({ host: '127.0.0.1', port, username: 'test-user', password: 'test-password', tls: false, timeoutMs: 2000 });
  try {
    await client.connect();
    const [first, second] = await Promise.all([
      client.print('/first', ['name']),
      client.print('/second', ['name']),
    ]);
    assert.deepEqual(first, [{ name: 'first-result' }]);
    assert.deepEqual(second, [{ name: 'second-result' }]);
  } finally {
    await client.close();
  }
  assert.deepEqual(received, ['/login', '/first/print', '/second/print']);
});

test('times out when RouterOS accepts TCP but never answers API login', async (t) => {
  const peer = net.createServer((socket) => {
    let buffer = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const decoded = decodeSentence(buffer);
      if (decoded?.words[0] === '/login') {
        // Intentionally leave the login unanswered; the client must time out.
      }
    });
  });
  await new Promise((resolve) => peer.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => peer.close(resolve)));
  const { port } = peer.address();
  const client = new RouterOsApiClient({ host: '127.0.0.1', port, username: 'test-user', password: 'test-password', tls: false, timeoutMs: 100 });
  await assert.rejects(() => client.connect(), /Timed out waiting for a RouterOS API reply/);
  await client.close();
});
