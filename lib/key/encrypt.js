import { encryptKey, encryptSessionKey as openpgp_encryptSessionKey } from '../openpgp';
import { serverTime } from '../serverTime';

export const encryptSessionKey = ({ date = serverTime(), ...rest }) => openpgp_encryptSessionKey({ date, ...rest });
