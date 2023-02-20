import { encryptSessionKey as openpgp_encryptSessionKey, encryptKey as openpgp_encryptKey } from '../openpgp';
import { serverTime } from '../serverTime';

export const encryptSessionKey = ({ date = serverTime(), ...rest }) => openpgp_encryptSessionKey({ date, ...rest });
export const encryptKey = ({ config = {}, ...rest }) => (
    openpgp_encryptKey({
        ...rest,
        // user passwords go through bcrypt rounds, hence we can lower the iteration counts
        config: { ...config, s2kIterationCountByte: 96 }
    })
);
