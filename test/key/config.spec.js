import test from 'ava';
import '../helper';
import { config } from 'openpgp';

test('it sets the correct configuration on openpgp', async (t) => {
    t.is(config.allow_insecure_decryption_with_signing_keys, true);
    t.is(config.s2k_iteration_count_byte, 96);
    t.is(config.integrity_protect, true);
    t.is(config.use_native, true);
});