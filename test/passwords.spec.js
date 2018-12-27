import { describe, it } from 'mocha';
import assert from 'assert';

import './setup';
import { hashPassword, generateKeySalt, computeKeyPassword, expandHash } from '../lib/passwords';
import { hashedResult4, hashedResult0, hashedResult2, watResult } from './passwords.data';

describe('passwords', () => {
    it('should generate key salt', () => {
        const salt = generateKeySalt();
        assert.strictEqual(salt.length, 24);
    });

    it('should compute key password', async () => {
        const keyp = await computeKeyPassword('hello', 'ajHO5Xshwb9h9DcAExIkbg==');
        assert.strictEqual(keyp, 'vQp4euSvXpBygefcOfyhCbWmFgFmgeW');
    });

    it('should expand hash', async () => {
        const result = await expandHash('wat');
        assert.deepStrictEqual(result, watResult);
    });

    it('should hash password version 4', async () => {
        const hashed = await hashPassword({
            password: 'hello',
            username: 'user1',
            salt: '»¢põó<±Ò&',
            modulus: new Uint8Array(256),
            version: 4
        });
        assert.deepStrictEqual(hashed, hashedResult4);
    });

    it('should hash password version 3', async () => {
        const hashed = await hashPassword({
            password: 'hello',
            username: 'user1',
            salt: '»¢põó<±Ò&',
            modulus: new Uint8Array(256),
            version: 3
        });
        assert.deepStrictEqual(hashed, hashedResult4);
    });

    it('should hash password version 2', async () => {
        const hashed = await hashPassword({
            password: 'hello',
            username: 'user1',
            salt: '»¢põó<±Ò&',
            modulus: new Uint8Array(256),
            version: 2
        });
        assert.deepStrictEqual(hashed, hashedResult2);
    });

    it('should hash password version 1', async () => {
        const hashed = await hashPassword({
            password: 'hello',
            username: 'user1',
            salt: '»¢põó<±Ò&',
            modulus: new Uint8Array(256),
            version: 1
        });
        assert.deepStrictEqual(hashed, hashedResult2);
    });

    it('should hash password version 0', async () => {
        const hashed = await hashPassword({
            password: 'hello',
            username: 'user1',
            salt: '»¢põó<±Ò&',
            modulus: new Uint8Array(256),
            version: 0
        });
        assert.deepStrictEqual(hashed, hashedResult0);
    });
});
