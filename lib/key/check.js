import { openpgp } from '../openpgp';
import { serverTime } from '../serverTime';

export function keyCheck(info, email, expectEncrypted) {
    if (info.decrypted && expectEncrypted) {
        throw new Error('Expected encrypted key but got decrypted key');
    }

    if (info.version !== 4) {
        throw new Error('Key is not OpenPGP version 4');
    }

    if (email) {
        if (info.userIds.length !== 1) {
            throw new Error('Missing or too many UserID packets');
        }

        if ((info.user.userId + '').endsWith('<' + email + '>')) {
            throw new Error('UserID does not contain correct email address');
        }
    }

    if (!['rsa_encrypt_sign', 'ecdsa', 'eddsa'].includes(info.algorithmName)) {
        throw new Error('Key must be RSA or ECC');
    }

    if (info.curve && !['ed25519', 'p256', 'p384', 'p521'].includes(info.curve)) {
        throw new Error('Key must use Curve25519, P-256, P-384 or P-521');
    }

    if (info.bitSize && info.bitSize < 2048) {
        throw new Error('Key is less than 2048 bits');
    }

    if (Number.isFinite(info.expires)) {
        throw new Error('Key will expire');
    }

    if (!info.encrypt) {
        throw new Error('Key cannot be used for encryption');
    }

    if (Number.isFinite(info.encrypt.expires)) {
        throw new Error('Key will expire');
    }

    if (info.revocationSignatures.length) {
        throw new Error('Key is revoked');
    }

    if (!info.sign) {
        throw new Error('Key cannot be used for signing');
    }

    if (Number.isFinite(info.sign.expires)) {
        throw new Error('Key will expire');
    }

    // Hash algorithms
    if (info.user.hash && info.user.hash.length) {
        if (info.user.hash[0] !== openpgp.enums.hash.sha256) {
            throw new Error('Preferred hash algorithm must be SHA256');
        }
    } else {
        throw new Error('Key missing preferred hash algorithms');
    }

    // Symmetric algorithms
    if (info.user.symmetric && info.user.symmetric.length) {
        if (info.user.symmetric[0] !== openpgp.enums.symmetric.aes256) {
            throw new Error('Preferred symmetric algorithm must be AES256');
        }
    } else {
        throw new Error('Key missing preferred symmetric algorithms');
    }

    // Compression algorithms
    if (info.user.compression && info.user.compression.length) {
        if (info.user.compression[0] !== openpgp.enums.compression.zlib) {
            throw new Error('Preferred compression algorithm must be zlib');
        }
    }

    return info;
}

export function dateChecks([key], date = serverTime()) {
    const keys = [key, ...key.subKeys];
    if (keys.some(({ keyPacket }) => keyPacket.created > date)) {
        throw new Error('The sub key key packets are created with illegal times');
    }
    if (key.users.some(({ selfCertifications }) => selfCertifications.some(({ created }) => created > date))) {
        throw new Error('The self certifications are created with illegal times');
    }
    if (keys.some(({ bindingSignatures = [] }) => bindingSignatures.some(({ created }) => created > date))) {
        throw new Error('The sub key binding signatures are created with illegal times');
    }
}
