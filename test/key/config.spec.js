import test from 'ava';
import '../helper';
import { openpgp } from '../../lib/openpgp';

test('it sets the correct configuration on openpgp', async (t) => {
    t.is(openpgp.config.allow_insecure_decryption_with_signing_keys, true);
    t.is(openpgp.config.s2k_iteration_count_byte, 96);
    t.is(openpgp.config.integrity_protect, true);
    t.is(openpgp.config.use_native, true);
});
