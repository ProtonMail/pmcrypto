import test from 'ava';
import '../helper';
import { keyInfo } from '../../lib/pmcrypto';

import { creationkey, publickey, keyInfoResult } from './info.data';

const trimVersion = (str) => {
    return str.substr(str.indexOf('Comment: https'));
};

test('keyInfo result', async (t) => {
    const result = await keyInfo(publickey);
    // Remove up to openpgp.js version
    result.publicKeyArmored = trimVersion(result.publicKeyArmored);
    keyInfoResult.publicKeyArmored = trimVersion(keyInfoResult.publicKeyArmored);
    t.deepEqual(result, keyInfoResult);
});

test('expiration test', async (t) => {
    const { expires, dateError } = await keyInfo(publickey);
    t.is(expires.getTime(), new Date('2023-09-11T12:37:02.000Z').getTime());
    t.is(dateError, undefined);
});

test('creation test', async (t) => {
    const { dateError } = await keyInfo(creationkey, undefined, undefined, new Date('2019-01-01T00:00:00.000Z'));
    t.is(dateError, 'The self certifications are created with illegal times');
});
