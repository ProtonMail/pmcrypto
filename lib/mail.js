import { decryptPrivateKey } from './key/decrypt';
import { getMessage } from './message/utils';
import { decryptMessage } from './message/decrypt';

export async function checkMailboxPassword(prKey, prKeyPassCode, accessToken) {
    if (typeof prKey === 'undefined') {
        throw new Error('Missing private key.');
    }

    if (typeof prKeyPassCode === 'undefined') {
        throw new Error('Missing mailbox password.');
    }

    const privateKey = await decryptPrivateKey(prKey, prKeyPassCode);

    // It can be a clearText key
    if (!/^-----BEGIN PGP MESSAGE-----/.test(accessToken)) {
        return { password: prKeyPassCode, token: accessToken };
    }

    const message = await getMessage(accessToken);

    try {
        // this is the private key, use this and decryptMessage to get the access token
        const { data } = await decryptMessage({ message, privateKeys: [privateKey] });
        return { password: prKeyPassCode, token: data };
    } catch (err) {
        throw new Error('Wrong mailbox password.');
    }
}
