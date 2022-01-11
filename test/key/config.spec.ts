import { expect } from 'chai';
import { openpgp } from '../../lib/openpgp';

describe('comfig', () => {
    it('it sets the correct configuration on openpgp', () => {
        // @ts-ignore missing type declaration for config.allow_insecure_decryption_with_signing_keys
        expect(openpgp.config.allow_insecure_decryption_with_signing_keys).to.equal(true);
        expect(openpgp.config.s2k_iteration_count_byte).to.equal(96);
        expect(openpgp.config.integrity_protect).to.equal(true);
        expect(openpgp.config.use_native).to.equal(true);
    });
});
