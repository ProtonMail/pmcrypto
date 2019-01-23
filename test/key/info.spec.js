import { describe, it } from 'mocha';
import assert from 'assert';

import '../setup';
import { keyInfo } from '../../lib';
import { creationkey, publickey } from './info.data';

describe('info', () => {
    it('should not give a date error', async () => {
        const { expires, dateError } = await keyInfo(publickey);
        assert.strictEqual(expires.getTime(), new Date('2023-09-11T12:37:02.000Z').getTime());
        assert.strictEqual(dateError, null);
    });

    it('should give a date error', async () => {
        const { dateError } = await keyInfo(creationkey);
        assert.strictEqual(dateError, 'The self certifications are created with illegal times');
    });
});
