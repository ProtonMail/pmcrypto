import { openpgp } from '../openpgp';
import { cloneKey } from './utils';
import { serverTime } from '../serverTime';

export function encryptPrivateKey(inputKey, privKeyPassCode) {
    return Promise.resolve(cloneKey(inputKey)).then((privKey) => {
        if (Object.prototype.toString.call(privKeyPassCode) !== '[object String]' || privKeyPassCode === '') {
            return Promise.reject(new Error('Missing private key passcode'));
        }

        if (!{}.isPrototypeOf.call(openpgp.key.Key.prototype, privKey)) {
            return Promise.reject(new Error('Not a Key object'));
        }

        if (!privKey.isPrivate()) {
            return Promise.reject(new Error('Not a private key'));
        }

        if (privKey.keyPacket === null || privKey.subKeys === null || privKey.subKeys.length === 0) {
            return Promise.reject(new Error('Missing primary key or subkey'));
        }

        return privKey.encrypt(privKeyPassCode).then(() => privKey.armor());
    });
}

export const encryptSessionKey = ({ date = serverTime(), ...rest }) => openpgp.encryptSessionKey({ date, ...rest });
