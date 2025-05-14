import { expect } from 'chai';
import { config, SymEncryptedSessionKeyPacket } from '../lib/openpgp';
import { decryptMessage, readMessage, VERIFICATION_STATUS, verifyMessage, readKey, readSignature, readPrivateKey } from '../lib';

const rsaSignOnly = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xcLYBF9Gl+MBCACc09O3gjyO0B1ledGxGFSUpPmhhJzkxKoY1WDX8VlASCHz
bAA/BytgYBXHTe7N+N3yJ6uiN3DIQ2j5uGWk/h5jyIOsRuzQxJ40n8AdK/71
SGDCG1X5l1h9vmVTJxkQ3pcOxqRg55EEuJWKN1v7B1hIPxhaM5hgH/7s+PNn
lQddckQJqYkpm9Hy6EI7f9oHrOtWJWZoCHkWZVld7+9ZVPi34ex5ofYOuvNL
AIKZCc7lAiUiDJYQ+hIJRoYwLYhjIshpYoHgNeG4snlupNO32BiwDbHFDjeu
eoBLQ0rxZV7B664ceCmIl+VRht9G20hfGoTjAiop5tyrN1ZeL4EaI+aTABEB
AAEAB/oCKTQnftvHwrkBVlyzSN6tfXylF2551Q3n4CZGg3efI/9PCa9wF58+
WApqmgsUqcNbVnDfl2T58ow05FLMxnFFNnHJq8ltfnXl+gG6c7iy94p79SQE
AGCOL7xNassXrDAQZhqWkCdiLK3b6r9F8Y3URb/AYbWH2BkFkS0oWQDav+Tw
lABt5vG2L5QtnShdqi8CCitcHGEKHocPHp0yAQlp3oAMq09YubgrzESDJ7Pe
l93cT35NlyimAZ6IYk/gumX0/6spqcw7205KfG6P84WlMp3WmE0IUWtiOp+7
rjMjDki0WeVKtuLbHBhOwKvxcILWz+0vQf3uu6aXOKQ3JlsVBADHoXa6QjrT
RmKD9ch65Pkd+EZiKhe+pqqIArVj4QsVBEnaggR59SD8uXhtpyBnvOp3xpof
Vut3SKWl/jmH7vKansFbHOo8xLUyVctu7lCL2/v85FcRJxfPK00MBic+z/vf
mWOAY1VBoi5I9qi6o8vVHA5BJ/xw2uV9VpxfiLG0vwQAyRxHmoZl/OxaZUsm
J9eDYV9xyYumkTCYvHPk9X+ehS+XeYh24z1q9a/1jEnSR3A5XE67UCLaspiA
+Px7nSU1+ftJ9bC2bnRR0Upop+3UkPeCBVp4tYAhsNnPXhSWC0gCgeGU7EmW
DechFg29LId35LXKgmXls9u5yDy2w978Hy0D/jbKZaxNMMwlx/XCFCoBEcXS
DBzg7GHNXdillJqy215j46lfVqOCB3IiffNKjHua2l6fQc0BoiWIZnElMnIa
faEBBSpOVqKhktDFacHa5xChjqXZVyw68qc0I36xkCfcwvYCpNKKkXv90r8A
tRI6gpBLeMJvkL3VkmKd6AZymxFxRGjNEkJvYiA8aW5mb0Bib2IuY29tPsLA
jQQQAQgAIAUCX0aX4wYLCQcIAwIEFQgKAgQWAgEAAhkBAhsDAh4BACEJEAr9
x5ZY6oZmFiEEm+B7p+lshgEOwGGZCv3HlljqhmaUWgf/efmGSpOKIGQ3Kh32
HUqn/4ARvUmqMtZz4xUA9P3GAPY8XwJf00jSQlAo4//3aA1eEOJFHCr2qzCk
/4gIoZEScTTZp4itfL/Fer3UX+bV/VeTNgZGi+MRylSDQxLRQNpRgu+FmRAi
E6fr8D8GMvEcGb0jTRgWGj1EVtfOHfDg+EyPrtw+Z8u/bErUJ+Fnxz+KOGSN
SBQVAOflUYFoQhUNgZiq1s8WFD55sfes3UdBwsmHquDtYGo9dvWLJXxTEF8q
QCyKHYdk25ShIlNpRUqOH3CHqY/38z7QeV7INwtZaQvoES08RlD6ZMtczYLj
BZou86lozq7ISvRg1RSIWZ0ZRA==
=A9Ts
-----END PGP PRIVATE KEY BLOCK-----
`;

const oldReformattedKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEYWmlshYJKwYBBAHaRw8BAQdAAxpFNPiHxz9q4HBzWqveHdP/knjwlgv8
pEQCMHDpIZIAAP9WFlwHDuVlvNb7CyoikwmG01nmdMDe9wXQRWA5vasWKA+g
zSV0ZXN0QHJlZm9ybWF0LmNvbSA8dGVzdEByZWZvcm1hdC5jb20+wowEEBYK
AB0FAmFppjQECwkHCAMVCAoEFgACAQIZAQIbAwIeAQAhCRAOZNKOg+/XQxYh
BGqP/hIaYCSJsZ4TrQ5k0o6D79dD+c8BAIXdh2hrC+l49WPN/KZF+ZzvWCWa
W5n+ozbp/sOGXvODAP4oGEj0RUDDA33b6x7fhQysBZxdrrnHxP9AXEdOTQC3
CsddBGFppbISCisGAQQBl1UBBQEBB0Cjy8Z2K7rl6J6AK1lCfVozmyLE0Gbv
1cspce6oCF6oCwMBCAcAAP9OL5V80EaYm2ic19aM+NtTj4UNOqKqIt10AaH9
SlcdMBDgwngEGBYIAAkFAmFppjQCGwwAIQkQDmTSjoPv10MWIQRqj/4SGmAk
ibGeE60OZNKOg+/XQx/EAQCM0UYrObp60YbOCxu07Dm6XjCVylbOcsaxCnE7
2eMU4AD+OkgajZgbqSIdAR1ud76FW+W+3xlDi/SMFdU7D49SbQI=
=ASQu
-----END PGP PRIVATE KEY BLOCK-----
`;

describe('openpgp configuration', () => {
    it('it sets the correct configuration for `allowInsecureDecryptionWithSigningKeys`', async () => {
        expect(config.allowInsecureDecryptionWithSigningKeys).to.be.true;

        const encryptedRsaSignOnly = `-----BEGIN PGP MESSAGE-----
    
wcBMAwr9x5ZY6oZmAQf+Lxghg4keIFpEq8a65gFkIfW+chHTDPlfI8xnx6U9
HdsICX3Oye5V0ToCVKkEWDxfN1yCfXiYalSNo7ScRZKR7C+j02/pC+FfR6AJ
2cvdFoGIrLaXdjXXc/oXbsCCZA4C1DhQqpdORo2qGF0Q6Sm8659B0CfOgYSL
fBfKQ5VJngUT5JG8Uek3YuXBufPNhzdmXLHyB2Y2CwKkldi2vo4YNAukDhrR
2TojxdNoouhnMm+gloCE1n8huY1vw5F78/uiHen0tmHQ0dxtfk8cc1burgl/
zUdJ3Sg6Eu+OC2ae5II63iB5fG+lCwZtfuepWnePDv8RDKNHCVP/LoBNpGOZ
U9I6AUkZWdcsueib9ghKDDy+HbUbf2kCJWUnuyeOCKqQifDb8bsLmdQY4Wb6
EBeLgD8oZHVsH3NLjPakPw==
=STqy
-----END PGP MESSAGE-----`;
        const key = await readPrivateKey({ armoredKey: rsaSignOnly });
        // decryption should succeed
        const { data } = await decryptMessage({
            message: await readMessage({ armoredMessage: encryptedRsaSignOnly }),
            decryptionKeys: key
        });
        expect(data).to.equal('hi');
    });

    it('it sets the correct configuration for `allowInsecureVerificationWithReformattedKeys`', async () => {
        expect(config.allowInsecureVerificationWithReformattedKeys).to.be.true;

        const armoredSignature = `-----BEGIN PGP SIGNATURE-----

wnUEARYKAAYFAmFppbIAIQkQDmTSjoPv10MWIQRqj/4SGmAkibGeE60OZNKO
g+/XQw1sAQClJ0Vl4z9x01udtYg/w54CueJmEt33kM4Q6JIZGIzt1AD9GZbG
EoSmib14fiYL0eQTz4I1XJ9OCVVZcaoFZzKnlQc=
=+BzR
-----END PGP SIGNATURE-----
`;
        // the key was reformatted and the message signature date preceeds the key self-signature creation date
        const key = await readKey({ armoredKey: oldReformattedKey });

        // since the key is valid at the current time, the message should be verifiable if the `config` allows it
        const { verificationStatus } = await verifyMessage({
            textData: 'plaintext',
            signature: await readSignature({ armoredSignature }),
            verificationKeys: key
        });
        expect(verificationStatus).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);
    });

    it('it sets the correct configuration for `enforceGrammar`', async () => {
        expect(config.enforceGrammar).to.be.false;

        const skeskPlusLiteralData = `-----BEGIN PGP MESSAGE-----

wy4ECQMIjvrInhvTxJwAbkqXp+KWFdBcjoPn03jCdyspVi9qXBDbyGaP1lrM
habAyxd1AGKaNp1wbGFpbnRleHQgbWVzc2FnZQ==
=XoUx
-----END PGP MESSAGE-----
        `;

        const message = await readMessage({ armoredMessage: skeskPlusLiteralData });
        expect(message.packets[0]).to.be.instanceOf(SymEncryptedSessionKeyPacket);

        await expect(
            readMessage({ armoredMessage: skeskPlusLiteralData, config: { enforceGrammar: true } })
        ).to.be.rejectedWith(/Data does not respect OpenPGP grammar/);
    });
});
