import { expect } from 'chai';
// @ts-ignore missing isStream definitions
import { isStream, readToEnd } from '@openpgp/web-stream-tools';
import { concatArrays, decodeBase64, encodeBase64, hexStringToArray, stringToUtf8Array, utf8ArrayToString } from '../lib/utils';
import type { Data } from '../lib';

const streamFromChunks = <T extends Data>(chunks: T[]) => {
    const it = chunks.values();
    return new ReadableStream<T>({
        pull: (controller) => {
            const { value, done } = it.next();
            if (done) {
                controller.close();
            } else {
                controller.enqueue(value);
            }
        }
    });
}

describe('utils', () => {
    it('concatArrays - it can correctly concatenate a single array', async () => {
        const arrays = [new Uint8Array([1, 2, 3])];
        const concatenated = concatArrays(arrays);
        expect(concatenated).to.deep.equal(new Uint8Array([1, 2, 3]));
    });

    it('concatArrays - it can correctly concatenate multiple arrays', async () => {
        const arrays = [new Uint8Array([1]), new Uint8Array([2, 3])];
        const concatenated = concatArrays(arrays);
        expect(concatenated).to.deep.equal(new Uint8Array([1, 2, 3]));
    });

    it('utf8ArrayToString - it can decode a Uint8Array', async () => {
        const utf8 = hexStringToArray('68656c6c6f20776f726c64');
        const decoded = utf8ArrayToString(utf8);
        expect(isStream(decoded)).to.be.false;
        expect(decoded).to.equal('hello world');
    });

    it('utf8ArrayToString - it can decode a stream', async () => {
        const utf8Stream = streamFromChunks(['68656c6c6f', '20776f726c64'].map(hexStringToArray));
        const decoded = utf8ArrayToString(utf8Stream);
        expect(isStream(decoded)).to.not.be.false;
        expect(await readToEnd(decoded)).to.equal('hello world');
    });

    it('utf8ArrayToString - it can decode a stream with utf8 chars across chunks', async () => {
        const utf8Stream = streamFromChunks(['f09f', '9982'].map(hexStringToArray));
        const decoded = utf8ArrayToString(utf8Stream);
        expect(isStream(decoded)).to.not.be.false;
        expect(await readToEnd(decoded)).to.equal('🙂');
    });

    it('utf8ArrayToString - it does not ignore a trailing partial utf8 char', async () => {
        const utf8Stream = streamFromChunks(['f09f', '9982', 'f09f'].map(hexStringToArray)); // emoji + half emoji
        const decoded = utf8ArrayToString(utf8Stream);
        expect(isStream(decoded)).to.not.be.false;
        expect(await readToEnd(decoded)).to.equal('🙂\uFFFD');
    });

    it('stringToUtf8Array - it can encode a string', async () => {
        const text = 'hello world';
        const encoded = stringToUtf8Array(text);
        expect(isStream(encoded)).to.be.false;
        expect(encoded).to.deep.equal(hexStringToArray('68656c6c6f20776f726c64'));
    });

    it('stringToUtf8Array - it can encode a stream', async () => {
        const textStream = streamFromChunks(['hello ', 'world']);
        const encoded = stringToUtf8Array(textStream);
        expect(isStream(encoded)).to.not.be.false;
        expect(await readToEnd(encoded)).to.deep.equal(hexStringToArray('68656c6c6f20776f726c64'));
    });

    it('encodeBase64 - it can correctly encode base 64', async () => {
        expect(encodeBase64('foo')).to.equal('Zm9v');
    });

    it('decodeBase64 - it can correctly decode base 64', async () => {
        expect(decodeBase64('Zm9v')).to.equal('foo');
    });
});
