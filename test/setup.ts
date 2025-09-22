import { use as chaiUse } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import { init, updateServerTime } from '../lib';

chaiUse(chaiAsPromised);
before(() => {
    // set server time in the future to spot functions that use local time unexpectedly
    const HOUR = 3600 * 1000;
    updateServerTime(new Date(Date.now() + HOUR));
    init();
});
