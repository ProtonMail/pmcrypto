import { beforeAll } from 'vitest';

import { init, updateServerTime } from '../lib';

beforeAll(() => {
    // set server time in the future to spot functions that use local time unexpectedly
    const HOUR = 3600 * 1000;
    updateServerTime(new Date(Date.now() + HOUR));
    init();
});
