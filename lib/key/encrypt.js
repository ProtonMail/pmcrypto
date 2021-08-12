import { PrivateKey, encryptKey, encryptSessionKey as openpgpEncryptSessionKey } from 'openpgp';
import { cloneKey } from './utils';
import { serverTime } from '../serverTime';

export function encryptPrivateKey(inputKey, privKeyPassCode) {
    return Promise.resolve(cloneKey(inputKey)).then((privKey) => {
        if (Object.prototype.toString.call(privKeyPassCode) !== '[object String]' || privKeyPassCode === '') {
            return Promise.reject(new Error('Missing private key passcode'));
        }

        if (!{}.isPrototypeOf.call(PrivateKey.prototype, privKey)) {
            return Promise.reject(new Error('Not a Key object'));
        }

        if (privKey.keyPacket === null || privKey.subKeys === null || privKey.subkeys.length === 0) {
            return Promise.reject(new Error('Missing primary key or subkey'));
        }

        return encryptKey({ privateKey: privKey, passphrase: privKeyPassCode }).then((encryptedKey) =>
            encryptedKey.armor()
        );
    });
}

export const encryptSessionKey = ({ date = serverTime(), ...rest }) => openpgpEncryptSessionKey({ date, ...rest });
