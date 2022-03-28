import { expect, use as chaiUse } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import {
    readPrivateKey as openpgp_readPrivateKey,
    decryptKey as openpgp_decryptKey,
    readKey as openpgp_readKey
} from '../../lib/openpgp';
import { VERIFICATION_STATUS, CryptoWorker } from '../../lib';
import { generateKey } from '../../lib/pmcrypto';

chaiUse(chaiAsPromised);

describe('Worker Pool', () => {
    before(async () => {
        await CryptoWorker.init(2);
    });

    afterEach(() => {
        CryptoWorker.clearKeyStore();
    });

    after(async () => {
        await CryptoWorker.destroy();
    })

    it('should encrypt/sign and decrypt/verify text and binary data', async () => {
        const aliceKeyRef = await CryptoWorker.generateKey({ userIDs: { name: 'alice', email: 'alice@test.com' } });
        const bobKeyRef = await CryptoWorker.generateKey({ userIDs: { name: 'bob', email: 'bob@test.com' } });

        const { message: encryptedArmoredMessage } = await CryptoWorker.encryptMessage({
            textData: 'hello world',
            encryptionKeys: bobKeyRef,
            signingKeys: aliceKeyRef
        });

        const textDecryptionResult = await CryptoWorker.decryptMessage({
            armoredMessage: encryptedArmoredMessage,
            decryptionKeys: bobKeyRef,
            verificationKeys: aliceKeyRef
        });
        expect(textDecryptionResult.data).to.equal('hello world');
        expect(textDecryptionResult.signatures).to.have.length(1);
        expect(textDecryptionResult.errors).to.not.exist;
        expect(textDecryptionResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);

        const { message: encryptedBinaryMessage } = await CryptoWorker.encryptMessage({
            binaryData: new Uint8Array([1, 2, 3]),
            encryptionKeys: bobKeyRef,
            signingKeys: aliceKeyRef,
            format: 'binary'
        });

        const binaryDecryptionResult = await CryptoWorker.decryptMessage({
            binaryMessage: encryptedBinaryMessage,
            decryptionKeys: bobKeyRef,
            verificationKeys: aliceKeyRef,
            format: 'binary'
        });
        expect(binaryDecryptionResult.data).to.deep.equal(new Uint8Array([1, 2, 3]));
        expect(binaryDecryptionResult.signatures).to.have.length(1);
        expect(binaryDecryptionResult.errors).to.not.exist;
        expect(binaryDecryptionResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    describe('Key management API', () => {

        it('can export a generated key', async () => {
            const privateKeyRef = await CryptoWorker.generateKey({ userIDs: { name: 'name', email: 'email@test.com' } });

            const passphrase = 'passphrase';
            const armoredKey = await CryptoWorker.exportPrivateKey({ keyReference: privateKeyRef, passphrase });
            const binaryKey = await CryptoWorker.exportPrivateKey({ keyReference: privateKeyRef, passphrase, format: 'binary' });

            const decryptedKeyFromArmored = await openpgp_decryptKey({
                privateKey: await openpgp_readPrivateKey({ armoredKey }),
                passphrase
            });
            expect(decryptedKeyFromArmored.isDecrypted()).to.be.true;

            const decryptedKeyFromBinary = await openpgp_decryptKey({
                privateKey: await openpgp_readPrivateKey({ binaryKey }),
                passphrase
            });
            expect(decryptedKeyFromBinary.isDecrypted()).to.be.true;
        });

        it('can export an imported key', async () => {
            const passphrase = 'passphrase';
            const { privateKey: keyToImport } = await generateKey({ userIDs: { name: 'name', email: 'email@test.com' }, format: 'object', passphrase });

            const importedKeyRef = await CryptoWorker.importPrivateKey({ armoredKey: keyToImport.armor(), passphrase });
            expect(importedKeyRef.getCreationTime()).to.deep.equal(keyToImport.getCreationTime());
            expect(
                importedKeyRef.subkeys.map((subkey) => subkey.getAlgorithmInfo())
            ).to.deep.equal(keyToImport.subkeys.map((subkey) => subkey.getAlgorithmInfo()));
            expect(importedKeyRef.getUserIDs()).to.deep.equal(['name <email@test.com>']);
            const armoredPublicKey = await CryptoWorker.exportPublicKey({ keyReference: importedKeyRef });
            const exportedPublicKey = await openpgp_readKey({ armoredKey: armoredPublicKey });
            expect(exportedPublicKey.isPrivate()).to.be.false;
            expect(exportedPublicKey.getKeyID().toHex()).equals(importedKeyRef.getKeyID())
            expect(exportedPublicKey.getKeyID().equals(keyToImport.getKeyID()));

            const exportPassphrase = 'another passphrase';
            const armoredPrivateKey = await CryptoWorker.exportPrivateKey({
                keyReference: importedKeyRef, passphrase: exportPassphrase
            });
            const exportedPrivateKey = await openpgp_readPrivateKey({ armoredKey: armoredPrivateKey });
            expect(exportedPrivateKey.getKeyID().equals(keyToImport.getKeyID()));
            // make sure the exported key is encrypted with the new passphrase
            const decryptedExportedKey = await openpgp_decryptKey({
                privateKey: exportedPrivateKey,
                passphrase: exportPassphrase
            });
            expect(decryptedExportedKey.isDecrypted()).to.be.true;
        });

        it('reformatted key has a separate key reference', async () => {
            const passphrase = 'passphrase';
            const originalKeyRef = await CryptoWorker.importPrivateKey({
                armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----

xYYEYjh/NRYJKwYBBAHaRw8BAQdAAJW2i9biFMIXiH15J6vGU1GCAqcp5utw
C+y+CeZ+h4L+CQMI/K3Ebi8BpsUAzexw43SwgpD0mDGd/d4ORX77AiUoq/rp
DKjS+0lpIszAa6SVWcA6xQZsz1ztdNBktEg4t/gybivH88kGTIprO/HWetM+
j80RPHRlc3RAd29ya2VyLmNvbT7CjAQQFgoAHQUCYjh/NQQLCQcIAxUICgQW
AAIBAhkBAhsDAh4BACEJEFx55sPEaXlKFiEE+PdMNIqw4jCyqqnuXHnmw8Rp
eUoC8QD+NdQzOAWdIJEp1eMeEa3xx9rkCpD2TXUeV7goHtixyQIBANcgmRTg
gN0O2hdiL9kjN4MPhbkz3dNTpkiO/K6O8UIDx4sEYjh/NRIKKwYBBAGXVQEF
AQEHQF3XUaFXbb6O9Qcas72x5nhNupZ3iIrIx8wKeUdgdkBNAwEIB/4JAwjK
CPlfkyHxBABYJC70HwO36TjRBxROY480CvL40r1bJ3NSLlV4aIZXLP2723PH
tsnD3fhK5ZbGqC7FCmmDKEh1ibl3Lw6rEoE0Z6Fq72x6wngEGBYIAAkFAmI4
fzUCGwwAIQkQXHnmw8RpeUoWIQT490w0irDiMLKqqe5ceebDxGl5Sl9wAQC+
9Jb0r5pG7sMbNclmp3s1OIfWG9tJ9RoXSHU/bCFHlgEA/ggjJKzRuja0MWZ6
8IDTErKCgaYSPES5+mwT27LYvw0=
=D7EW
-----END PGP PRIVATE KEY BLOCK-----`,
                passphrase
            });

            const reformattedKeyRef = await CryptoWorker.reformatKey({ keyReference: originalKeyRef, userIDs: { email: 'reformatted@worker.com' } });
            expect(reformattedKeyRef.getUserIDs()).to.have.length(1);
            expect(reformattedKeyRef.getUserIDs().includes('<reformatted@worker.com>'));
            expect(originalKeyRef.getUserIDs()).to.have.length(1);
            expect(originalKeyRef.getUserIDs()).includes('<test@worker.com>');

            await CryptoWorker.clearKey({ keyReference: originalKeyRef }); // this clears the private params as well

            const armoredKey = await CryptoWorker.exportPrivateKey({ keyReference: reformattedKeyRef, passphrase });
            const decryptedKeyFromArmored = await openpgp_decryptKey({
                privateKey: await openpgp_readPrivateKey({ armoredKey }),
                passphrase
            });
            expect(decryptedKeyFromArmored.isDecrypted()).to.be.true;
        });

        it('clearKey - cannot reference a cleared key', async () => {
            const privateKeyRef = await CryptoWorker.generateKey({ userIDs: { name: 'name', email: 'email@test.com' } });
            // confirm key is in the store
            expect(await CryptoWorker.exportPublicKey({ keyReference: privateKeyRef })).length.above(0);
            await CryptoWorker.clearKey({ keyReference: privateKeyRef });

            await expect(CryptoWorker.exportPublicKey({ keyReference: privateKeyRef })).to.be.rejectedWith(/Key not found/);
        });

        it('clearKeyStore - cannot reference any key after clearing the store', async () => {
            const privateKeyRef1 = await CryptoWorker.generateKey({ userIDs: { name: 'name', email: 'email@test.com' } });
            const privateKeyRef2 = await CryptoWorker.generateKey({ userIDs: { name: 'name', email: 'email@test.com' } });
            // (lazily) confirm that keys are in the store
            expect(await CryptoWorker.exportPublicKey({ keyReference: privateKeyRef1 })).length.above(0);
            expect(await CryptoWorker.exportPublicKey({ keyReference: privateKeyRef2 })).length.above(0);
            await CryptoWorker.clearKeyStore();

            await expect(CryptoWorker.exportPublicKey({ keyReference: privateKeyRef1 })).to.be.rejectedWith(/Key not found/);
            await expect(CryptoWorker.exportPublicKey({ keyReference: privateKeyRef2 })).to.be.rejectedWith(/Key not found/);
        });

    });
});
