import test from 'ava';
import '../helper';

import { generateForwardingMaterial, proxyTransform } from '../../lib/pmcrypto';
import { openpgp } from '../../lib/openpgp';

test('generate forwarding key', async (t) => {
    const options = { userIds: [{ name: 'Bob', email: 'info@bob.com' }], curve: 'curve25519' };
    const { key } = await openpgp.generateKey(options);
    const bobKey = key;
    // Generate keyId for later checks
    bobKey.getKeyId();

    return generateForwardingMaterial(bobKey, [{ name: 'Charlie', email: 'info@charlie.com' }]).then(
        async ({ finalRecipientKey }) => {
            const charlieKey = finalRecipientKey.key;

            // Check primary key differences
            t.is(charlieKey.getKeyId().equals(bobKey.getKeyId()), false);
            t.notDeepEqual(charlieKey.keyPacket.keyMaterial, bobKey.keyPacket.keyMaterial);
            t.deepEqual(charlieKey.keyPacket.params[0], bobKey.keyPacket.params[0]); // OID
            t.notDeepEqual(charlieKey.keyPacket.params[1], bobKey.keyPacket.params[1]);
            t.notDeepEqual(charlieKey.keyPacket.params[2], bobKey.keyPacket.params[2]);

            // Check subkey differences
            const bobSubKey = await bobKey.getEncryptionKey();
            const charlieSubKey = await charlieKey.getEncryptionKey();
            t.is(charlieSubKey.getKeyId().equals(bobSubKey.getKeyId()), false);
            t.notDeepEqual(charlieSubKey.keyPacket.keyMaterial, bobSubKey.keyPacket.keyMaterial);
            t.deepEqual(charlieSubKey.keyPacket.params[0], bobSubKey.keyPacket.params[0]); // OID
            t.notDeepEqual(charlieSubKey.keyPacket.params[1], bobSubKey.keyPacket.params[1]);
            t.notDeepEqual(charlieSubKey.keyPacket.params[2], bobSubKey.keyPacket.params[2]);
            t.notDeepEqual(charlieSubKey.keyPacket.params[3], bobSubKey.keyPacket.params[3]);
            // Check KDF params
            t.is(charlieSubKey.keyPacket.params[2].version, 2);
            t.is(charlieSubKey.keyPacket.params[2].flags, 0x3);
            t.is(
                openpgp.util.Uint8Array_to_hex(charlieSubKey.keyPacket.params[2].replacementFingerprint),
                bobSubKey.getFingerprint()
            );
            t.deepEqual(
                new openpgp.KDFParams(charlieSubKey.keyPacket.params[2]).replacementKDFParams,
                bobSubKey.keyPacket.params[2].write()
            );
        }
    );
});

test('decryption with forwarding - v4 key', async (t) => {
    const options = { userIds: [{ name: 'Bob', email: 'info@bob.com' }], curve: 'curve25519' };
    const { key } = await openpgp.generateKey(options);
    const bobKey = key;
    const plaintext = 'Hello Bob, hello world';
    const ciphertext = await openpgp.encrypt({
        message: openpgp.message.fromText(plaintext),
        publicKeys: bobKey.toPublic()
    });
    const ciphertextData = await openpgp.message.readArmored(ciphertext.data);

    const { proxyFactor, finalRecipientKey } = await generateForwardingMaterial(bobKey, [
        { name: 'Bob', email: 'info@bob.com', comment: 'Forwarded to Charlie' }
    ]);
    const charlieKey = finalRecipientKey.key;

    const transformedCiphertext = await proxyTransform(
        ciphertextData,
        proxyFactor,
        bobKey.subKeys[0].getKeyId(),
        charlieKey.subKeys[0].getKeyId()
    );
    const decrypted = await openpgp.decrypt({
        message: transformedCiphertext,
        privateKeys: charlieKey
    });
    t.is(decrypted.data, plaintext);

    // Charlie cannot decrypt the original ciphertext
    const decryptionTrial = openpgp.decrypt({
        message: await openpgp.message.readArmored(ciphertext.data),
        privateKeys: charlieKey
    });
    const error = await t.throwsAsync(decryptionTrial);
    t.regex(error.message, /Session key decryption failed/);
});

test.serial('decryption with forwarding - v5 key', async (t) => {
    openpgp.config.v5_keys = !openpgp.config.v5_keys;
    const options = { userIds: [{ name: 'Bob', email: 'info@bob.com' }], curve: 'curve25519' };
    const { key } = await openpgp.generateKey(options);
    const bobKey = key;
    const plaintext = 'Hello Bob, hello world';
    const ciphertext = await openpgp.encrypt({
        message: openpgp.message.fromText(plaintext),
        publicKeys: bobKey.toPublic()
    });
    const ciphertextData = await openpgp.message.readArmored(ciphertext.data);

    const { proxyFactor, finalRecipientKey } = await generateForwardingMaterial(bobKey, [
        { name: 'Bob', email: 'info@bob.com', comment: 'Forwarded to Charlie' }
    ]);
    const charlieKey = finalRecipientKey.key;
    t.is(bobKey.keyPacket.version, 5);
    t.is(charlieKey.keyPacket.version, 5);

    const transformedCiphertext = await proxyTransform(
        ciphertextData,
        proxyFactor,
        bobKey.subKeys[0].getKeyId(),
        charlieKey.subKeys[0].getKeyId()
    );
    const decrypted = await openpgp.decrypt({
        message: transformedCiphertext,
        privateKeys: charlieKey
    });
    t.is(decrypted.data, plaintext);
    openpgp.config.v5_keys = !openpgp.config.v5_keys;
});
