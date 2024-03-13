import { expect } from 'chai';
import { PublicKeyEncryptedSessionKeyPacket, AEADEncryptedDataPacket } from '../../lib/openpgp';
import { stripArmor, splitMessage, armorBytes, readMessage } from '../../lib';
import { removeTrailingSpaces } from '../../lib/message/utils';

describe('message utils', () => {
    it('stripArmor - it can correctly dearmor a message', async () => {
        const x = await stripArmor(`
-----BEGIN PGP MESSAGE-----
Version: GnuPG v2.0.19 (GNU/Linux)

jA0ECQMCpo7I8WqsebTJ0koBmm6/oqdHXJU9aPe+Po+nk/k4/PZrLmlXwz2lhqBg
GAlY9rxVStLBrg0Hn+5gkhyHI9B85rM1BEYXQ8pP5CSFuTwbJ3O2s67dzQ==
=VZ0/
-----END PGP MESSAGE-----`);
        expect(x).to.deep.equal(new Uint8Array([
            140, 13, 4, 9, 3, 2, 166, 142, 200, 241, 106, 172, 121, 180, 201,
            210, 74, 1, 154, 110, 191, 162, 167, 71, 92, 149, 61, 104, 247,
            190, 62, 143, 167, 147, 249, 56, 252, 246, 107, 46, 105, 87, 195,
            61, 165, 134, 160, 96, 24, 9, 88, 246, 188, 85, 74, 210, 193, 174,
            13, 7, 159, 238, 96, 146, 28, 135, 35, 208, 124, 230, 179, 53, 4,
            70, 23, 67, 202, 79, 228, 36, 133, 185, 60, 27, 39, 115, 182, 179,
            174, 221, 205
        ]));
    });

    it('armorBytes - it can correctly enarmor a message', async () => {
        const armored = await armorBytes(new Uint8Array([
            140, 13, 4, 9, 3, 2, 166, 142, 200, 241, 106, 172, 121, 180, 201,
            210, 74, 1, 154, 110, 191, 162, 167, 71, 92, 149, 61, 104, 247,
            190, 62, 143, 167, 147, 249, 56, 252, 246, 107, 46, 105, 87, 195,
            61, 165, 134, 160, 96, 24, 9, 88, 246, 188, 85, 74, 210, 193, 174,
            13, 7, 159, 238, 96, 146, 28, 135, 35, 208, 124, 230, 179, 53, 4,
            70, 23, 67, 202, 79, 228, 36, 133, 185, 60, 27, 39, 115, 182, 179,
            174, 221, 205
        ]));

        // the armored message differs from GPG's because of the new header format
        expect(armored).to.equal(`-----BEGIN PGP MESSAGE-----

ww0ECQMCpo7I8WqsebTJ0koBmm6/oqdHXJU9aPe+Po+nk/k4/PZrLmlXwz2l
hqBgGAlY9rxVStLBrg0Hn+5gkhyHI9B85rM1BEYXQ8pP5CSFuTwbJ3O2s67d
zQ==
-----END PGP MESSAGE-----
`);
    });

    it('splitMessage - it can correctly split a message', async () => {
        const armoredMessage = `-----BEGIN PGP MESSAGE-----

wV4D+XE4B6yFCrUSAQdAur2W1bvOByAj6fDqTNLLCED/QO9StAS5MKr0ud6l
0hswcvpQaq/Bup46mgO2n2f1hgv9wwlKq7hYYyHJWJ631Ai4yifFZy+rnAv/
kGXdMLE/1EcBCQEMWzWe+L8qO3Vq0Yr7aLeW93PCFLxl+J9wQMIqnl4EiOYh
sJFJxllC0j4wHCOS9uiSYsZ/pWCqxX/3sFh4VBFOpr0HAA==
=S5ns
-----END PGP MESSAGE-----`;

        const message = await readMessage({ armoredMessage });
        const packets = await splitMessage(message);
        expect(packets.asymmetric).to.have.length(1);
        expect(packets.symmetric).to.have.length(0);
        expect(packets.encrypted).to.have.length(1);
        const pkesk = await readMessage({ binaryMessage: packets.asymmetric[0] });
        expect(pkesk.packets[0]).to.be.instanceOf(PublicKeyEncryptedSessionKeyPacket);
        const aeadData = await readMessage({ binaryMessage: packets.encrypted[0] });
        expect(aeadData.packets[0]).to.be.instanceOf(AEADEncryptedDataPacket);
    });

    it('removeTrailingSpaces - it can correctly normalise the text', async () => {
        const data = 'BEGIN:VCARD\r\nVERSION:4.0\r\nFN;PREF=1:   \r\nEND:VCARD';
        const expected = 'BEGIN:VCARD\nVERSION:4.0\nFN;PREF=1:\nEND:VCARD';
        expect(removeTrailingSpaces(data)).to.equal(expected);
    });
});
