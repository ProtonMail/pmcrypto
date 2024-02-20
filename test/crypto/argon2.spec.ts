import { expect } from 'chai';
import { argon2 } from '../../lib';
import { ARGON2_PARAMS } from '../../lib/constants';
import { arrayToHexString, hexStringToArray } from '../../lib/utils';

describe('argon2 key derivation', () => {
    it('basic test - minimum recommended params', async () => {
        const expected = '6904f1422410f8360c6538300210a2868f5e80cd88606ec7d6e7e93b49983cea';
        const passwordBytes = hexStringToArray('0101010101010101010101010101010101010101010101010101010101010101');
        const tag = await argon2({
            password: new TextDecoder().decode(passwordBytes),
            salt: hexStringToArray('0202020202020202020202020202020202020202020202020202020202020202'),
            params: ARGON2_PARAMS.MINIMUM
        });
        expect(arrayToHexString(tag)).to.equal(expected);
    });
});
