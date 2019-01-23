import { describe, it } from 'mocha';
import assert from 'assert';

import '../setup';
import { openpgp } from '../../lib/openpgp';

describe('config', () => {
    it('should set the correct configuration on openpgp', () => {
        assert.strictEqual(openpgp.config.s2k_iteration_count_byte, 96);
        assert.strictEqual(openpgp.config.integrity_protect, true);
        assert.strictEqual(openpgp.config.use_native, true);
    });
});
