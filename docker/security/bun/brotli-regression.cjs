// Regression vector from Node.js v24.22.1, test-zlib-invalid-input.js.
const assert = require('node:assert/strict');
const zlib = require('node:zlib');
const { createServer } = require('node:http');

async function main() {
    const invalid = Buffer.from('200010414141fcffff07002228f00b60f7f41f000000', 'hex');
    const expected = { code: 'ERR__ERROR_FORMAT_BLOCK_SWITCH', errno: -17 };
    assert.equal(zlib.constants.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH, -17);
    assert.throws(() => zlib.brotliDecompressSync(invalid), expected);
    const text = 'racconify brotli regression '.repeat(400);
    const compressed = zlib.brotliCompressSync(Buffer.from(text));
    assert.equal(zlib.brotliDecompressSync(compressed).toString(), text);
    await new Promise((resolve, reject) => {
        const stream = zlib.createBrotliDecompress();
        stream.resume();
        stream.on('end', () => reject(new Error('Malformed Brotli was accepted')));
        stream.on('error', error => {
            try { assert.equal(error.code, expected.code); assert.equal(error.errno, -17); resolve(); }
            catch (failure) { reject(failure); }
        });
        for (const byte of invalid) stream.write(Buffer.from([byte]));
        stream.end();
    });
    const server = createServer((request, response) => {
        response.writeHead(200, { 'content-encoding': 'br', 'connection': 'close' });
        response.end(request.url === '/valid' ? compressed : invalid);
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
        const url = `http://127.0.0.1:${server.address().port}`;
        assert.equal(await (await fetch(url + '/valid')).text(), text);
        await assert.rejects(async () => (await fetch(url + '/invalid')).arrayBuffer());
    } finally { await new Promise(resolve => server.close(resolve)); }
    console.log(JSON.stringify({ node: process.version, bun: process.versions.bun || null, brotli: process.versions.brotli || null, brotliRegressionPassed: true }));
}
const timeout = setTimeout(() => process.exit(2), 15000);
main().then(() => clearTimeout(timeout)).catch(error => { clearTimeout(timeout); console.error(error); process.exitCode = 1; });
