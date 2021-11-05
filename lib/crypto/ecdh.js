import nacl from '@openpgp/tweetnacl/nacl-fast-light';
import { concatUint8Array } from '@openpgp/web-stream-tools';
import { enums } from 'openpgp';
import { getRandomBytes, binaryStringToArray } from '../utils';
import { SHA256 } from './hash';

const CURVE25519_PARAMS = {
    oid: new Uint8Array([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]),
    keyType: enums.publicKey.ecdh,
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
    payloadSize: 32
};

const AES_KEYSIZE = {
    aes128: 16,
    aes192: 12,
    aes256: 32
};

/**
 * Get ECDHE X25519 ephemeral shared secret from long-term private scalar and ephemeral public point
 *
 * @param  {Uint8Array} V Ephemeral public key
 * @param  {Uint8Array} d Long-term private key
 * @returns {Promise<{secretKey: Uint8Array, sharedKey: Uint8Array}>}
 * @async
 */
export async function generateX25519PrivateEphemeralKey(V, d) {
    const secretKey = d.slice().reverse();
    // Reconstruct ephemeral secret: dV = d(vG) = v(dG) = vQ = S (with v in little endian and base curve point G)
    const sharedKey = nacl.scalarMult(secretKey, V.subarray(1));
    return { secretKey, sharedKey };
}

/**
 * Generate ECDHE X25519 ephemeral public key and shared secret, for a given recipient
 * @param  {Uint8Array} Q Recipient public key
 * @returns {Promise<{publicKey: Uint8Array, sharedKey: Uint8Array}>}
 * @async
 */
export async function generateX25519PublicEphemeralKey(Q) {
    // Sample ephemeral secret scalar (and interpret as little-endian)
    const v = await getRandomBytes(CURVE25519_PARAMS.payloadSize);
    const secretKey = v.slice().reverse();
    // Ephemeral shared secret S = vQ (with v in little endian)
    const sharedKey = nacl.scalarMult(secretKey, Q.subarray(1));
    // ephemeral public V = vG (with curve base point G)
    let { publicKey } = nacl.box.keyPair.fromSecretKey(secretKey);
    publicKey = concatUint8Array([new Uint8Array([0x40]), publicKey]);
    return { publicKey, sharedKey };
}

// Key Derivation Function (RFC 6637)
// Note: X is little endian for Curve25519.
// This is not ideal, but the RFC's are unclear
// https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-02#appendix-B\
export async function KDF(X, fingerprint) {
    const digest = await SHA256(
        concatUint8Array([
            new Uint8Array([0, 0, 0, 1]),
            X,
            // KDF params
            CURVE25519_PARAMS.oid,
            new Uint8Array([CURVE25519_PARAMS.keyType, 3, 1, CURVE25519_PARAMS.hash, CURVE25519_PARAMS.cipher]),
            binaryStringToArray('Anonymous Sender    '),
            fingerprint.subarray(0, 20)
        ])
    );

    const length = AES_KEYSIZE[CURVE25519_PARAMS.cipher];
    return digest.subarray(0, length);
}
