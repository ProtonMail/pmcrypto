// eslint-disable-next-line camelcase
import { encryptKey, encryptSessionKey as openpgp_encryptSessionKey } from 'openpgp';
import { serverTime } from '../serverTime';

export async function encryptPrivateKey(privateKey, passphrase) {
    return encryptKey({ privateKey, passphrase }).then((encryptedKey) => encryptedKey.armor());
}

export const encryptSessionKey = ({ date = serverTime(), ...rest }) => openpgp_encryptSessionKey({ date, ...rest });
