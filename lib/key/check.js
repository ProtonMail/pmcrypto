import openpgpjs from '../openpgp';

export default function keyCheck(info, email, expectEncrypted) {

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

        if (!(new RegExp('<' + email + '>$').test(info.user.userId))) {
            throw new Error('UserID does not contain correct email address');
        }
    }

    if (info.bitSize && info.bitSize < 1024) {
        throw new Error('Key is less than 1024 bits');
    }

    if (isFinite(info.expires)) {
        throw new Error('Key will expire');
    }

    if (!info.encrypt) {
        throw new Error('Key cannot be used for encryption');
    }

    if (isFinite(info.encrypt.expires)) {
        throw new Error('Key will expire');
    }

    if (info.revocationSignatures.length) {
        throw new Error('Key is revoked');
    }

    if (!info.sign) {
        throw new Error('Key cannot be used for signing');
    }

    if (isFinite(info.sign.expires)) {
        throw new Error('Key will expire');
    }

    // Hash algorithms
    if (info.user.hash && info.user.hash.length) {
        if (info.user.hash[0] !== openpgpjs.enums.hash.sha256) {
            throw new Error('Preferred hash algorithm must be SHA256');
        }
    } else {
        throw new Error('Key missing preferred hash algorithms');
    }

    // Symmetric algorithms
    if (info.user.symmetric && info.user.symmetric.length) {
        if (info.user.symmetric[0] !== openpgpjs.enums.symmetric.aes256) {
            throw new Error('Preferred symmetric algorithm must be AES256');
        }
    } else {
        throw new Error('Key missing preferred symmetric algorithms');
    }

    // Compression algorithms
    if (info.user.compression && info.user.compression.length) {
        if (info.user.compression[0] !== openpgpjs.enums.compression.zlib) {
            throw new Error('Preferred compression algorithm must be zlib');
        }
    }

    return info;
}
