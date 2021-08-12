import { openpgp } from '../lib/openpgp';
import test from 'ava';
import { unsafeMD5, unsafeSHA1, arrayToHexString, binaryStringToArray } from '../lib/utils';

globalThis.crypto = require('crypto').webcrypto;

test('md5 basic test', async (t) => {
    const emptyHash = arrayToHexString(await unsafeMD5(new Uint8Array([])));
    const testHash = arrayToHexString(
        await unsafeMD5(binaryStringToArray('The quick brown fox jumps over the lazy dog'))
    );
    t.is(emptyHash, 'd41d8cd98f00b204e9800998ecf8427e');
    t.is(testHash, '9e107d9d372bb6826bd81d3542a419d6');
});

test('sha1 basic test', async (t) => {
    const emptyHash = arrayToHexString(await unsafeSHA1(new Uint8Array([])));
    const testHash = arrayToHexString(await unsafeSHA1(binaryStringToArray('abc')));
    t.is(emptyHash, 'da39a3ee5e6b4b0d3255bfef95601890afd80709');
    t.is(testHash, 'a9993e364706816aba3e25717850c26c9cd0d89d');
});
