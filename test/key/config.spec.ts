import test from 'ava';
import '../helper';
import { config, readMessage, readPrivateKey } from 'openpgp';
import { decryptMessage } from '../../lib';

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

test('it sets the correct configuration on openpgp', async (t) => {
    t.is(config.s2kIterationCountByte, 96);
    t.is(config.allowInsecureDecryptionWithSigningKeys, true);

    // ensure that `allowInsecureDecryptionWithSigningKeys` is applied
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
    t.is(data, 'hi');
});
