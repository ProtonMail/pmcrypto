import { expect } from 'chai';
import { ec as EllipticCurve } from 'elliptic';
import BN from 'bn.js';

import { decryptKey, enums, type PublicKeyEncryptedSessionKeyPacket, type KeyID, type PacketList } from '../../lib/openpgp';
import { generateKey, generateForwardingMaterial, doesKeySupportForwarding, encryptMessage, decryptMessage, readMessage, readKey, readPrivateKey, serverTime } from '../../lib';
import { computeProxyParameter, isForwardingKey } from '../../lib/key/forwarding';
import { hexStringToArray, concatArrays, arrayToHexString } from '../../lib/utils';

// this is only intended for testing purposes, due to BN.js dependency, which is huge
async function testProxyTransform(
    armoredCiphertext: string,
    proxyParameter: Uint8Array<ArrayBuffer>,
    originalSubkeyID: KeyID,
    finalRecipientSubkeyID: KeyID
) {
    const curve = new EllipticCurve('curve25519');

    const ciphertext = await readMessage({ armoredMessage: armoredCiphertext });
    for (
        // missing PublicKeyEncryptedSessionKeyPacket field declarations
        const packet of ciphertext.packets.filterByTag(
            enums.packet.publicKeyEncryptedSessionKey
        ) as PacketList<PublicKeyEncryptedSessionKeyPacket>
    ) {
        // @ts-expect-error missing `publicKeyID` field declaration
        if (packet.publicKeyID.equals(originalSubkeyID)) {
            // @ts-expect-error missing `encrypted` field
            const bG = packet.encrypted.V;
            const point = curve.curve.decodePoint(bG.subarray(1).reverse());
            const bkG = new Uint8Array(
                point
                    .mul(new BN(proxyParameter, 'le'))
                    .getX()
                    .toArray('le', 32)
            );
            const encoded = concatArrays([new Uint8Array([0x40]), bkG]);
            // @ts-expect-error missing `encrypted` field
            packet.encrypted.V = encoded;
            // @ts-expect-error missing `publicKeyID` field
            packet.publicKeyID = finalRecipientSubkeyID;
        }
    }

    return ciphertext.armor();
}

describe('forwarding', () => {
    it('can decrypt forwarded ciphertext', async () => {
        const charlieKeyArmored = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEZAdtGBYJKwYBBAHaRw8BAQdAcNgHyRGEaqGmzEqEwCobfUkyrJnY8faBvsf9
R2c5ZzYAAP9bFL4nPBdo04ei0C2IAh5RXOpmuejGC3GAIn/UmL5cYQ+XzRtjaGFy
bGVzIDxjaGFybGVzQHByb3Rvbi5tZT7CigQTFggAPAUCZAdtGAmQFXJtmBzDhdcW
IQRl2gNflypl1XjRUV8Vcm2YHMOF1wIbAwIeAQIZAQILBwIVCAIWAAIiAQAAJKYA
/2qY16Ozyo5erNz51UrKViEoWbEpwY3XaFVNzrw+b54YAQC7zXkf/t5ieylvjmA/
LJz3/qgH5GxZRYAH9NTpWyW1AsdxBGQHbRgSCisGAQQBl1UBBQEBB0CxmxoJsHTW
TiETWh47ot+kwNA1hCk1IYB9WwKxkXYyIBf/CgmKXzV1ODP/mRmtiBYVV+VQk5MF
EAAA/1NW8D8nMc2ky140sPhQrwkeR7rVLKP2fe5n4BEtAnVQEB3CeAQYFggAKgUC
ZAdtGAmQFXJtmBzDhdcWIQRl2gNflypl1XjRUV8Vcm2YHMOF1wIbUAAAl/8A/iIS
zWBsBR8VnoOVfEE+VQk6YAi7cTSjcMjfsIez9FYtAQDKo9aCMhUohYyqvhZjn8aS
3t9mIZPc+zRJtCHzQYmhDg==
=lESj
-----END PGP PRIVATE KEY BLOCK-----`;

        const fwdCiphertextArmored = `-----BEGIN PGP MESSAGE-----

wV4DB27Wn97eACkSAQdA62TlMU2QoGmf5iBLnIm4dlFRkLIg+6MbaatghwxK+Ccw
yGZuVVMAK/ypFfebDf4D/rlEw3cysv213m8aoK8nAUO8xQX3XQq3Sg+EGm0BNV8E
0kABEPyCWARoo5klT1rHPEhelnz8+RQXiOIX3G685XCWdCmaV+tzW082D0xGXSlC
7lM8r1DumNnO8srssko2qIja
=pVRa
-----END PGP MESSAGE-----`;
        const charlieKey = await readPrivateKey({ armoredKey: charlieKeyArmored });

        await expect(decryptMessage({
            message: await readMessage({ armoredMessage: fwdCiphertextArmored }),
            decryptionKeys: charlieKey
        })).to.be.rejectedWith(/Error decrypting message/); // missing config flag

        const result = await decryptMessage({
            message: await readMessage({ armoredMessage: fwdCiphertextArmored }),
            decryptionKeys: charlieKey,
            config: { allowForwardedMessages: true }
        });

        expect(result.data).to.equal('Message for Bob');
    });

    it('proxy parameter computation is correct', async () => {
        const secretBob = hexStringToArray('5989216365053dcf9e35a04b2a1fc19b83328426be6bb7d0a2ae78105e2e3188');
        const secretCharlie = hexStringToArray('684da6225bcd44d880168fc5bec7d2f746217f014c8019005f144cc148f16a00');

        const expectedProxyFactor = hexStringToArray('e89786987c3a3ec761a679bc372cd11a425eda72bd5265d78ad0f5f32ee64f02');
        const actualProxyFactor = await computeProxyParameter(secretBob, secretCharlie);

        expect(actualProxyFactor).to.deep.equal(expectedProxyFactor);
    });

    it('generate forwarding key', async () => {
        const { privateKey: bobKey } = await generateKey({ userIDs: [{ name: 'Bob', email: 'info@bob.com' }], format: 'object' });

        const { forwardeeKey } = await generateForwardingMaterial(bobKey, [{ name: 'Charlie', email: 'info@charlie.com' }]);
        const charlieKey = await readKey({ armoredKey: forwardeeKey.armor() }); // ensure key is correctly serialized and parsed

        // Check subkey differences
        const bobSubkey = await bobKey.getEncryptionKey(undefined, serverTime());
        const charlieSubkey = charlieKey.subkeys[0];

        expect(charlieSubkey.bindingSignatures[0].keyFlags![0]).to.equal(enums.keyFlags.forwardedCommunication);
        // @ts-ignore oid field not defined
        expect(charlieSubkey.keyPacket.publicParams.oid).to.deep.equal(bobSubkey.keyPacket.publicParams.oid);
        // Check KDF params
        // @ts-ignore kdfParams field not defined
        const charlieSubkeyKDFParams = charlieSubkey.keyPacket.publicParams.kdfParams;
        // @ts-ignore kdfParams field not defined
        const bobSubkeyKDFParams = bobSubkey.keyPacket.publicParams.kdfParams;
        expect(charlieSubkeyKDFParams.hash).to.equal(bobSubkeyKDFParams.hash);
        expect(charlieSubkeyKDFParams.cipher).to.equal(bobSubkeyKDFParams.cipher);
        expect(charlieSubkeyKDFParams.version).to.equal(0xFF);
        expect(
            charlieSubkeyKDFParams.replacementFingerprint
        ).to.deep.equal(bobSubkey.keyPacket.getFingerprintBytes());
    });

    it('generate forwarding key - KDF params hash and cipher are correctly copied over', async () => {
        // sha512 and aes256 as KDFParams options
        const bobKey = await readPrivateKey({ armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEZR5v2hYJKwYBBAHaRw8BAQdANGEppfpOvm+WZ2q2GZxRSo8FR3eIgJxC
Caeey6SO5KUAAP9Ipt8zxY7LnnNBGzlgcGiBA4qQNBZ6VecLdNgShl8AEg35
zQ48dGVzdEB0ZXN0Lml0PsKMBBAWCgA+BYJlH8uEBAsJBwgJkHXYKIC+P8wd
AxUICgQWAAIBAhkBApsDAh4BFiEEhJYaMQwPxUSp5y0BddgogL4/zB0AAL4i
AP9UkQvVedKAxiNvr4mGQOLRlOEHw1sZjil3wm6I0mcbnQD/e5zWQj7ToEOL
Pq5wc5guttKvMi5vXO+N7SjFdV7KTwPHXQRlHm/aEgorBgEEAZdVAQUBAQdA
jNr0MP98DXFIB4Ge1ydzGV0GW2W+OrVvVSioj7p/PU0DAQoJAAD/bZITV/Pf
5Xz6Btg820PoeZY8AseQT0vOkJ5R3pOW8KgS38J4BBgWCAAqBYJlH8uECZB1
2CiAvj/MHQKbDBYhBISWGjEMD8VEqectAXXYKIC+P8wdAACdTgEA6vGgdMfI
S6CP/U6uXws66mIgL7CmFVMKqLLJaASqcQwA/isDrUVgBnhkwF+IPZvEUZY3
P0GnopWOyFNNFWK77LQN
=Lyee
-----END PGP PRIVATE KEY BLOCK-----` });

        const { forwardeeKey } = await generateForwardingMaterial(bobKey, [{ name: 'Charlie', email: 'info@charlie.com' }]);
        const charlieKey = await readKey({ armoredKey: forwardeeKey.armor() }); // ensure key is correctly serialized and parsed

        // Check subkey differences
        const bobSubkey = await bobKey.getEncryptionKey();
        const charlieSubkey = charlieKey.subkeys[0];

        expect(charlieSubkey.bindingSignatures[0].keyFlags![0]).to.equal(enums.keyFlags.forwardedCommunication);
        // @ts-ignore oid field not defined
        expect(charlieSubkey.keyPacket.publicParams.oid).to.deep.equal(bobSubkey.keyPacket.publicParams.oid);

        // Check KDF params
        // @ts-ignore kdfParams field not defined
        const charlieSubkeyKDFParams = charlieSubkey.keyPacket.publicParams.kdfParams;
        // @ts-ignore kdfParams field not defined
        const bobSubkeyKDFParams = bobSubkey.keyPacket.publicParams.kdfParams;
        expect(charlieSubkeyKDFParams.hash).to.equal(bobSubkeyKDFParams.hash);
        expect(charlieSubkeyKDFParams.cipher).to.equal(bobSubkeyKDFParams.cipher);
        expect(charlieSubkeyKDFParams.version).to.equal(0xFF);
        expect(
            charlieSubkeyKDFParams.replacementFingerprint
        ).to.deep.equal(bobSubkey.keyPacket.getFingerprintBytes());
    });

    it('generate forwarding key - should throw for P256 encryption key', async () => {
        const keyWithP256Subkey = await readPrivateKey({ armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----

xXcEZNI7SRMIKoZIzj0DAQcCAwRNbEFVQ7/5dkZsMEObzf2bL6bYLg7UmbOL
nC8LG9BWIfEmTH3QNOO2IuJDRyF/WmqpoNXQBuO7Emophg+23x1WAAD+JRQA
cUMAXKtqmey7d06r7EHIYyE/dgZeGo/z0WKmmjcO5M0OPHRlc3RAdGVzdC5p
dD7CiQQQEwgAOwWCZNI7SQMLCQcJkLi5pXUe27CfAxUICgIWAAIZAQKbAwIe
ARYhBEJtG+YOG/wgLGeeOri5pXUe27CfAADxkAEA4dh2u60jIlRo5yMwSBeb
nDEuRrt4M1XNs78OgDkHv0QBALrQuKGEP7UVo5O6Vr0ah91O5VAcC9XxwjtY
xl1CersLx3sEZNI7SRIIKoZIzj0DAQcCAwQTk1ESj08ix1DHXGW4ZQ5KiQNi
KL3z6+KiYnjEDNjsPtH4o0FHS6d5zUmEXZ1xqbGcOmOKZ8YgKyNklYu3T5g1
AwEIBwABAKdySgrgktTT86zgFJRkxpPkNDhMRFpBj9APRJZE1NhlEIPCeAQY
EwgAKgWCZNI7SQmQuLmldR7bsJ8CmwwWIQRCbRvmDhv8ICxnnjq4uaV1Htuw
nwAAwa4BAPslluPut3qHU2h7PB+D93ttxCn/AhSgOc5lUOafZt2VAP91FuPa
8ziVOrUmQTj0eOBjfW0XYIlm7JTERrRlh5S8R8ddBGTSO0kSCisGAQQBl1UB
BQEBB0CrsfLaOT7JAcwc2vg36SSJ6YCXODfvudM9INHNA3kxcQMBCAcAAP9h
0r01q6Jz/KvfNkJXzkvfaAfXOe6GfrFs10QvTvjpwBL4wngEGBMIACoFgmTS
O0kJkLi5pXUe27CfApsMFiEEQm0b5g4b/CAsZ546uLmldR7bsJ8AAGnuAQCF
lAWga4MJBiFLbBiYD7248zu+xmvUAWBU7f/dkHenYAD+K8UCcwQrqeDhCl0q
z5FbOJXSHsoez1SZ7GKgoxC+X0w=
-----END PGP PRIVATE KEY BLOCK-----` });

        await expect(
            generateForwardingMaterial(keyWithP256Subkey, [{ name: 'Charlie', email: 'info@charlie.com' }])
        ).to.be.rejectedWith(/unsuitable for forwarding/);
    });

    it('decryption with forwarding - v4 key', async () => {
        const { privateKey: bobKey } = await generateKey({
            userIDs: [{ name: 'Bob', email: 'info@bob.com' }], curve: 'curve25519Legacy', format: 'object'
        });
        const plaintext = 'Hello Bob, hello world';

        const { proxyInstances, forwardeeKey: charlieKey } = await generateForwardingMaterial(bobKey, [
            { name: 'Charlie', email: 'info@charlie.com', comment: 'Forwarded from Bob' }
        ]);
        expect(proxyInstances).to.have.length(1);
        // check proxyInstance data
        expect(proxyInstances[0].keyVersion).to.equal(4);
        expect(
            arrayToHexString(proxyInstances[0].forwarderKeyFingerprint)
        ).to.include(bobKey.subkeys[0].getKeyID().toHex());
        expect(
            arrayToHexString(proxyInstances[0].forwardeeKeyFingerprint)
        ).to.include(charlieKey.subkeys[0].getKeyID().toHex());

        const { message: originalCiphertext } = await encryptMessage({
            textData: plaintext,
            encryptionKeys: bobKey
        });

        const transformedCiphertext = await testProxyTransform(
            originalCiphertext,
            proxyInstances[0].proxyParameter,
            bobKey.subkeys[0].getKeyID(),
            charlieKey.subkeys[0].getKeyID()
        );
        const { data: decryptedData } = await decryptMessage({
            message: await readMessage({ armoredMessage: transformedCiphertext }),
            decryptionKeys: charlieKey,
            config: { allowForwardedMessages: true }
        });
        expect(decryptedData).to.equal(plaintext);

        // Charlie cannot decrypt the original ciphertext
        const decryptionTrialPromise = decryptMessage({
            message: await readMessage({ armoredMessage: originalCiphertext }),
            decryptionKeys: charlieKey,
            config: { allowForwardedMessages: true }
        });
        expect(decryptionTrialPromise).to.be.rejectedWith(/Error decrypting message/);
    });

    it('decryption with forwarding - v4 key with multiple subkeys', async () => {
        const { privateKey: bobKey } = await generateKey({
            curve: 'curve25519Legacy',
            userIDs: [{ name: 'Bob', email: 'info@bob.com' }],
            subkeys: [{}, { sign: true }, {}], // ensure that signing subkey creates no issues
            format: 'object'
        });
        const plaintext = 'Hello Bob, hello world';

        const { proxyInstances, forwardeeKey: charlieKey } = await generateForwardingMaterial(bobKey, [
            { name: 'Charlie', email: 'info@charlie.com', comment: 'Forwarded from Bob' }
        ]);
        expect(proxyInstances).to.have.length(2);
        const bobForwardedSubkeys = [bobKey.subkeys[0], bobKey.subkeys[2]]; // exclude signing subkey

        proxyInstances.forEach((proxyInstance, i) => {
            expect(proxyInstance.keyVersion).to.equal(4);
            expect(
                arrayToHexString(proxyInstance.forwarderKeyFingerprint)
            ).to.include(bobForwardedSubkeys[i].getKeyID().toHex());
            expect(
                arrayToHexString(proxyInstance.forwardeeKeyFingerprint)
            ).to.include(charlieKey.subkeys[i].getKeyID().toHex());
        });

        // test first encryption subkey
        const { message: originalCiphertext1 } = await encryptMessage({
            textData: plaintext,
            encryptionKeys: bobKey
        });
        const transformedCiphertext1 = await testProxyTransform(
            originalCiphertext1,
            proxyInstances[0].proxyParameter,
            bobForwardedSubkeys[0].getKeyID(),
            charlieKey.subkeys[0].getKeyID()
        );
        const { data: decryptedData1 } = await decryptMessage({
            message: await readMessage({ armoredMessage: transformedCiphertext1 }),
            decryptionKeys: charlieKey,
            config: { allowForwardedMessages: true }
        });
        expect(decryptedData1).to.equal(plaintext);

        // test second encryption subkey
        // @ts-ignore missing `clone` definition
        const bobKeySecondEncryptionKey = bobKey.clone();
        bobKeySecondEncryptionKey.subkeys = [bobForwardedSubkeys[1]]; // keep second encryption subkey only

        const { message: originalCiphertext2 } = await encryptMessage({
            textData: plaintext,
            encryptionKeys: bobKeySecondEncryptionKey
        });
        const transformedCiphertext2 = await testProxyTransform(
            originalCiphertext2,
            proxyInstances[1].proxyParameter,
            bobForwardedSubkeys[1].getKeyID(),
            charlieKey.subkeys[1].getKeyID()
        );
        const { data: decryptedData2 } = await decryptMessage({
            message: await readMessage({ armoredMessage: transformedCiphertext2 }),
            decryptionKeys: charlieKey,
            config: { allowForwardedMessages: true }
        });
        expect(decryptedData2).to.equal(plaintext);
    });

    it('supports forwarding - should return false for key without encryption subkeys', async () => {
        // key one signing subkey (eddsa) and no encryption subkey
        const keyWithoutEncryptionSubkey = await readPrivateKey({ armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----

xXcEZNI7/RMIKoZIzj0DAQcCAwSNFSvjFVNYffbO5XUFvFJ5xESepuHQLQnh
W/tojHJokrXUDoJVAFsuY75WQazg+tijE9lwsqWoHfmx2+ON701pAAEAjlRL
J4b3p99h5PtitDhJ7oOsJ53/NBRnB9WEaWe/B3AQJM0OPHRlc3RAdGVzdC5p
dD7CiQQQEwgAOwWCZNI7/QMLCQcJkOysb71imEtxAxUICgIWAAIZAQKbAwIe
ARYhBDL/D8Jh/QrgN2oaheysb71imEtxAABgZgD/Y1SgPcpCNYjXE6Bl4W2p
VoGwWTQw5v4mfiHSK7qIBD8BAMJh3Yy4JLcOFrP1nHniSqTofzV7/WIhbC4S
4X6P0OJzx3cEZNI7/RMIKoZIzj0DAQcCAwTAEms2toyTFVJxVcVfaR1PTgXF
5b+NPxup3KIl76V0pVnj2MLo9ybrT9FmUtcPpnv0yPbupth574+cmjPuKUad
AAD/YqNbylQRJ1piWpcI49IuTM6ziVFDVYgEn0DnfwqmEI0OqsLALwQYEwgA
oQWCZNI7/QmQ7KxvvWKYS3ECmwJ2oAQZEwgAJwWCZNI7/QmQu8ngLvN7JUsW
IQSYVaNgBswfa0ijOye7yeAu83slSwAAnisA/35TkgN/YOzx7xmuyEB9gU3C
8QamMZYvYNSE3RcyS+fdAQCsrPkmzfOGiRoklhYfw/kVrePu8ZBkWYkv5t8M
tJ0UnxYhBDL/D8Jh/QrgN2oaheysb71imEtxAAASQQEA7Y/Kqi5PO0ippJWt
WVQQHpRSfwBq7E9MwabhzSONxcgA/iosiBLv2PRyLGLdr4Jv3U40c4UK/4vk
yhtWgu8zFVCg
-----END PGP PRIVATE KEY BLOCK-----` });
        expect(await doesKeySupportForwarding(keyWithoutEncryptionSubkey)).to.be.false;
    });

    it('supports forwarding - should return false for encryption subkey without private key material (gnu-dummy)', async () => {
        // key with two ecdh subkeys, one of which does not have private key material (gnu-dummy)
        const keyWithDummySubkey = await readPrivateKey({ armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEZNI5VxYJKwYBBAHaRw8BAQdAuT2PU1Ud1ouGL/M3IDL0T8Id7VCnJdli
W9kOy7uaYH8AAQC7PMst8kOBnhJr0zWjoKXBiACvWDoS7fy/4qbokPT3BxHn
zQ48dGVzdEB0ZXN0Lml0PsKJBBAWCgA7BYJk0jlXAwsJBwmQ0c3MqmerEnQD
FQgKAhYAAhkBApsDAh4BFiEEUAye1Mg4OC7HGN8X0c3MqmerEnQAADqMAP9f
8C71XjonSBjBX/itYIyzD7Hys6FvKukPwZLCg5bzaAEA9/6uSeuYaDLPzOpI
Cn4d/8Z7O8bDWD3dKKn7mNYNYgjHXQRk0jlXEgorBgEEAZdVAQUBAQdAFT64
s/Pg0veAEzjTmVJVC3qRG2tOLi55CZOeyhLXw20DAQgHAAD/RXHA/5cxbVUm
Y1+kAEgqbMni8ZNx0sKt4gBzoyI8M5gQasJ4BBgWCAAqBYJk0jlXCZDRzcyq
Z6sSdAKbDBYhBFAMntTIODguxxjfF9HNzKpnqxJ0AADD3wD/dC0/pPOOR4bW
n2L4G+VVB8Do/2vGvmlqsDBQEovc9hIBAMa0R31jAD+HaIMmlYGSitA3tfPF
Lo07Y7/piuY3Uh8Ox0AEZNI5VxIKKwYBBAGXVQEFAQEHQJ3zUcuB2xyrZ8gj
wD3yBLsmig1s+V3zNWJPET9C9YcjAwEIB/4JZQBHTlUBwngEGBYIACoFgmTS
OVcJkNHNzKpnqxJ0ApsMFiEEUAye1Mg4OC7HGN8X0c3MqmerEnQAACNMAP90
AxcnmfGjsJHMfjS4Bm7THR5NtVAdCsjjBnJKABbE/wEA5Rqdw2rwo14iIXR4
qEAteMrSvyBNSgSuY4BIpZJNygI=
-----END PGP PRIVATE KEY BLOCK-----` });
        expect(await doesKeySupportForwarding(keyWithDummySubkey)).to.be.false;
    });

    it('supports forwarding - should return false if an encryption subkey is NIST p256', async () => {
        // two ecdh subkeys: one curve25519, one p256
        const keyWithP256Subkey = await readPrivateKey({ armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----

xXcEZNI7SRMIKoZIzj0DAQcCAwRNbEFVQ7/5dkZsMEObzf2bL6bYLg7UmbOL
nC8LG9BWIfEmTH3QNOO2IuJDRyF/WmqpoNXQBuO7Emophg+23x1WAAD+JRQA
cUMAXKtqmey7d06r7EHIYyE/dgZeGo/z0WKmmjcO5M0OPHRlc3RAdGVzdC5p
dD7CiQQQEwgAOwWCZNI7SQMLCQcJkLi5pXUe27CfAxUICgIWAAIZAQKbAwIe
ARYhBEJtG+YOG/wgLGeeOri5pXUe27CfAADxkAEA4dh2u60jIlRo5yMwSBeb
nDEuRrt4M1XNs78OgDkHv0QBALrQuKGEP7UVo5O6Vr0ah91O5VAcC9XxwjtY
xl1CersLx3sEZNI7SRIIKoZIzj0DAQcCAwQTk1ESj08ix1DHXGW4ZQ5KiQNi
KL3z6+KiYnjEDNjsPtH4o0FHS6d5zUmEXZ1xqbGcOmOKZ8YgKyNklYu3T5g1
AwEIBwABAKdySgrgktTT86zgFJRkxpPkNDhMRFpBj9APRJZE1NhlEIPCeAQY
EwgAKgWCZNI7SQmQuLmldR7bsJ8CmwwWIQRCbRvmDhv8ICxnnjq4uaV1Htuw
nwAAwa4BAPslluPut3qHU2h7PB+D93ttxCn/AhSgOc5lUOafZt2VAP91FuPa
8ziVOrUmQTj0eOBjfW0XYIlm7JTERrRlh5S8R8ddBGTSO0kSCisGAQQBl1UB
BQEBB0CrsfLaOT7JAcwc2vg36SSJ6YCXODfvudM9INHNA3kxcQMBCAcAAP9h
0r01q6Jz/KvfNkJXzkvfaAfXOe6GfrFs10QvTvjpwBL4wngEGBMIACoFgmTS
O0kJkLi5pXUe27CfApsMFiEEQm0b5g4b/CAsZ546uLmldR7bsJ8AAGnuAQCF
lAWga4MJBiFLbBiYD7248zu+xmvUAWBU7f/dkHenYAD+K8UCcwQrqeDhCl0q
z5FbOJXSHsoez1SZ7GKgoxC+X0w=
-----END PGP PRIVATE KEY BLOCK-----` });
        expect(await doesKeySupportForwarding(keyWithP256Subkey)).to.be.false;
    });

    it('isForwardingKey', async () => {
        const signOnlyKey = await readPrivateKey({
            armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEZ4evPxYJKwYBBAHaRw8BAQdAz/OfKP1cqnXkjwiYbhvkPzPV4SBpc+IK
zc9j/limEXIAAQD7k7p8GpP5W9iMDFfNQZ/q8xFIiAQcbPXG/bcPVgYRvRAs
zQg8YUBhLml0PsLAEQQTFgoAgwWCZ4evPwMLCQcJkIHN0wt4lUcZRRQAAAAA
ABwAIHNhbHRAbm90YXRpb25zLm9wZW5wZ3Bqcy5vcmd4nycM2KL0cTS8Ttv0
mQFbx8Q+4bovdfed2qSvArkmPgMVCggEFgACAQIZAQKbAwIeARYhBNF4Mj8k
jFoxVyK1FYHN0wt4lUcZAACbsQEA+O5gxkeu+KDS1fdyNhPasqhPMbj5nEyl
fbFd4a5yy3kBAMSHD8k0/DSw7NPfO5XzHJ5hP0nhLjSFHOc8YjITQGcM
=0mtr
-----END PGP PRIVATE KEY BLOCK-----`
        });

        const charlieKeyEncrypted = await readPrivateKey({ armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----

xYYEZAdtGBYJKwYBBAHaRw8BAQdAcNgHyRGEaqGmzEqEwCobfUkyrJnY8faB
vsf9R2c5Zzb+CQMI0YEeYODMnX7/8Bm7rq3beejbyFxINLDKMehud14ePBBw
0t2bzVTtdpNDh1ck070XBO5oRF8zRzFw2ziyShz5KyA0MwQxu+B0q9rbJ2pl
C80bY2hhcmxlcyA8Y2hhcmxlc0Bwcm90b24ubWU+wooEExYIADwFAmQHbRgJ
kBVybZgcw4XXFiEEZdoDX5cqZdV40VFfFXJtmBzDhdcCGwMCHgECGQECCwcC
FQgCFgACIgEAACSmAP9qmNejs8qOXqzc+dVKylYhKFmxKcGN12hVTc68Pm+e
GAEAu815H/7eYnspb45gPyyc9/6oB+RsWUWAB/TU6VsltQLHnwRkB20YEgor
BgEEAZdVAQUBAQdAsZsaCbB01k4hE1oeO6LfpMDQNYQpNSGAfVsCsZF2MiAX
/woJil81dTgz/5kZrYgWFVflUJOTBRD+CQMIjcTRUSYiwLP/ectAkFq9iyz9
qXjJe4T8RAwMG7UDIhE89gwTwfbSBOxKWpg5v3H/Yk4Fi7LKrg5K3pdVxvrL
sAAEJmKlJMGXnZ4HOB75NsJ4BBgWCAAqBQJkB20YCZAVcm2YHMOF1xYhBGXa
A1+XKmXVeNFRXxVybZgcw4XXAhtQAACX/wD+IhLNYGwFHxWeg5V8QT5VCTpg
CLtxNKNwyN+wh7P0Vi0BAMqj1oIyFSiFjKq+FmOfxpLe32Yhk9z7NEm0IfNB
iaEO
=Szic
-----END PGP PRIVATE KEY BLOCK-----` });

        const charlieKey = await decryptKey({ privateKey: charlieKeyEncrypted, passphrase: 'passphrase' });

        const bobKey = await readPrivateKey({ armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEZAdtGBYJKwYBBAHaRw8BAQdAGzrOpvCFCxQ6hmpP52fBtbYmqkPM+TF9oBei
x9QWcnEAAQDa54PERHLvDqIMo0f03+mJXMTR3Dwq+qi5LTaflQFDGxEdzRNib2Ig
PGJvYkBwcm90b24ubWU+wooEExYIADwFAmQHbRgJkCLL+xMJ+Hy4FiEEm77zV6Zb
syLVIzOyIsv7Ewn4fLgCGwMCHgECGQECCwcCFQgCFgACIgEAAAnFAPwPoXgScgPr
KQFzu1ltPuHodEaDTtb+/wRQ1oAbuSdDgQD7B82NJgyEZInC/4Bwuc+ysFgaxW2W
gtypuW5vZm44FAzHXQRkB20YEgorBgEEAZdVAQUBAQdAeUTOhlO2RBUGH6B7127u
a82Mmjv62/GKZMpbNFJgqAcDAQoJAAD/Sd14Xkjfy1l8r0vQ5Rm+jBG4EXh2G8XC
PZgMz5RLa6gQ4MJ4BBgWCAAqBQJkB20YCZAiy/sTCfh8uBYhBJu+81emW7Mi1SMz
siLL+xMJ+Hy4AhsMAAAKagEA4Knj6S6nG24nuXfqkkytPlFTHwzurjv3+qqXwWL6
3RgA/Rvy/NcpCizSOL3tLLznwSag7/m6JVy9g6unU2mZ5QoI
=un5O
-----END PGP PRIVATE KEY BLOCK-----` });

        await expect(isForwardingKey(signOnlyKey)).to.eventually.be.false;
        await expect(isForwardingKey(charlieKeyEncrypted)).to.eventually.be.true;
        await expect(isForwardingKey(charlieKey)).to.eventually.be.true;
        await expect(isForwardingKey(bobKey)).to.eventually.be.false;
    });
});
