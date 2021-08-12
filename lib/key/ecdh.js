import nacl from '@openpgp/tweetnacl/nacl-fast-light';
import { concatUint8Array } from '@openpgp/web-stream-tools';
import { enums } from 'openpgp';
import { getRandomBytes, binaryStringToArray, SHA256 } from '../utils';

export const payloadSize = 32;
export const ECDHOid = [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];
export const ECDHHash = enums.hash.sha256;
export const ECDHCipher = enums.symmetric.aes128;

export async function genECDHPrivateEphemeralKey(V, Q, d) {
    const secretKey = d.slice().reverse();
    const sharedKey = nacl.scalarMult(secretKey, V.subarray(1));
    return { secretKey, sharedKey };
}

export async function genECDHPublicEphemeralKey(Q) {
    const d = await getRandomBytes(payloadSize);
    const { secretKey, sharedKey } = await genECDHPrivateEphemeralKey(Q, null, d);
    let { publicKey } = nacl.box.keyPair.fromSecretKey(secretKey);
    publicKey = concatUint8Array([new Uint8Array([0x40]), publicKey]);
    return { publicKey, sharedKey };
}

export function buildECDHParam(fingerprint) {
    return concatUint8Array([
        new Uint8Array(ECDHOid),
        new Uint8Array([enums.publicKey.ecdh]),
        new Uint8Array([3, 1, ECDHHash, ECDHCipher]),
        binaryStringToArray('Anonymous Sender    '),
        fingerprint.subarray(0, 20)
    ]);
}

export async function ECDHkdf(hashAlgo, X, param) {
    const digest = await SHA256(concatUint8Array([new Uint8Array([0, 0, 0, 1]), X, param]));
    return digest.subarray(0, 16);
}
