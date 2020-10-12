import nacl from 'tweetnacl/nacl-fast-light';
import { concatArrays, binaryStringToArray, getRandomBytes, SHA256, hexToUint8Array } from '../utils';

// Key Derivation Function (RFC 6637)
export async function kdf(X, length, param) {
    // Note: X is little endian for Curve25519, big-endian for all others.
    // This is not ideal, but the RFC's are unclear
    // https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-02#appendix-B\
    const digestResult = await SHA256(concatArrays([new Uint8Array([0, 0, 0, 1]), X, param]));
    return digestResult.subarray(0, length);
}

// Build Param for ECDH algorithm (RFC 6637)
export function buildEcdhParam(publicAlgo, fingerprint) {
    return concatArrays([
        hexToUint8Array('0A2B060104019755010501'),
        new Uint8Array([publicAlgo]),
        hexToUint8Array('03010807'),
        binaryStringToArray('Anonymous Sender    '),
        fingerprint.subarray(0, 20)
    ]);
}

/**
 * Generate ECDHE secret from private key and public part of ephemeral key
 *
 * @param  {Uint8Array}             V            Public part of ephemeral key
 * @param  {Uint8Array}             Q            Recipient public key
 * @param  {Uint8Array}             d            Recipient private key
 * @returns {Promise<{secretKey: Uint8Array, sharedKey: Uint8Array}>}
 * @async
 */
export async function genCurvePrivateEphemeralKey(V, Q, d) {
    if (d.length !== 32) {
        const privateKey = new Uint8Array(32);
        privateKey.set(d, 32 - d.length);
        d = privateKey;
    }
    const secretKey = d.slice().reverse();
    const sharedKey = nacl.scalarMult(secretKey, V.subarray(1));
    return { secretKey, sharedKey }; // Note: sharedKey is little-endian here
}

/**
 * Generate ECDHE ephemeral key and secret from public key
 *
 * @param  {Uint8Array}             Q            Recipient public key
 * @returns {Promise<{publicKey: Uint8Array, sharedKey: Uint8Array}>}
 * @async
 */
export async function genCurvePublicEphemeralKey(Q) {
    const d = await getRandomBytes(32);
    const { secretKey, sharedKey } = await genCurvePrivateEphemeralKey(Q, null, d);
    let { publicKey } = nacl.box.keyPair.fromSecretKey(secretKey);
    publicKey = concatArrays([new Uint8Array([0x40]), publicKey]);
    return { publicKey, sharedKey }; // Note: sharedKey is little-endian here
}
