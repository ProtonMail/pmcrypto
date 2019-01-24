import { it, describe } from 'mocha';
import assert from 'assert';

import '../setup';
import { concatArrays, decodeBase64, encodeBase64, stripArmor } from '../../lib/pmcrypto';
import { message, messageResult } from './utils.data';

describe('utils', () => {
    it('should correctly encode base 64', () => {
        assert.strictEqual(encodeBase64('foo'), 'Zm9v');
    });

    it('should correctly decode base 64', () => {
        assert.strictEqual(decodeBase64('Zm9v'), 'foo');
    });

    it('should correctly concat arrays', () => {
        assert.deepStrictEqual(concatArrays([new Uint8Array(1), new Uint8Array(1)]), new Uint8Array(2));
    });

    it('should correctly dearmor a message', async () => {
        assert.deepStrictEqual(await stripArmor(message), messageResult);
    });
});
