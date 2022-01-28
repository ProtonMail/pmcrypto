import { generateKey, utf8ArrayToString } from '..';

export const Api = {
  inc: () => {
    return 1;
  },

  generateKey,
  utf8ArrayToString

    // key store and management also here (not in proxy)
}
