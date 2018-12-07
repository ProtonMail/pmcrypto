import test from 'ava';
import '../helper';
import { concatArrays, decodeBase64, encodeBase64 } from '../../lib/pmcrypto';

test('it can correctly encode base 64', async (t) => {
    t.is(encodeBase64('foo'), 'Zm9v');
});

test('it can correctly decode base 64', async (t) => {
    t.is(decodeBase64('Zm9v'), 'foo');
});

test('it can correctly concat arrays', async (t) => {
    t.deepEqual(concatArrays([new Uint8Array(1), new Uint8Array(1)]), new Uint8Array(2));
});
