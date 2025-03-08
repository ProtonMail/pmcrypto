// eslint-disable-next-line no-restricted-imports -- allow chai imports in this file only
import { use as chaiUse, expect } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import { init, updateServerTime } from '../lib';

chaiUse(chaiAsPromised);
before(() => {
    // set server time in the future to spot functions that use local time unexpectedly
    const HOUR = 3600 * 1000;
    updateServerTime(new Date(Date.now() + HOUR));
    init();
});

// force importing `expect` through this module, so that chaiAsPromised and mocha's `before()`
// are also initialized as a side-effect
export { expect };
