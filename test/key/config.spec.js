import test from 'ava';
import '../helper';
import { config } from 'openpgp';

test('it sets the correct configuration on openpgp', async (t) => {
    t.is(config.allowInsecureDecryptionWithSigningKeys, true);
    t.is(config.s2kIterationCountByte, 96);
    t.is(config.integrityProtect, true);
    t.is(config.useNative, true);
});
