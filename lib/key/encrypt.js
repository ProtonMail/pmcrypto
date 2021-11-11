import { encryptKey, encryptSessionKey as openpgpEncryptSessionKey } from 'openpgp';
import { serverTime } from '../serverTime';

export async function encryptPrivateKey(privateKey, passphrase) {
    return encryptKey({ privateKey, passphrase }).then((encryptedKey) => encryptedKey.armor());
}

export const encryptSessionKey = ({ date = serverTime(), ...rest }) => openpgpEncryptSessionKey({ date, ...rest });
