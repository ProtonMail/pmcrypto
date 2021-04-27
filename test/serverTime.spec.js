import test from 'ava';

import { updateServerTime, serverTime } from '../lib';

const MILLISECONDS_1_HOUR = 3600 * 1000;
const oneHourAgo = new Date(Date.now() - MILLISECONDS_1_HOUR);
const oneDayAgo = new Date(Date.now() - MILLISECONDS_1_HOUR * 25);
const oneDayAhead = new Date(Date.now() + MILLISECONDS_1_HOUR * 25);

test('it correctly updates the server time', (t) => {
    const currentServerTime = serverTime();
    const updatedServerTime = updateServerTime(oneHourAgo);
    t.not(currentServerTime, updatedServerTime);
    t.is(updatedServerTime, oneHourAgo);
    t.is(updatedServerTime, serverTime());
});

test('it does not allow to set an older server time', (t) => {
    const currentTime = new Date();
    const updatedServerTime = updateServerTime(currentTime);
    t.is(currentTime, updatedServerTime);
    t.is(updateServerTime(oneHourAgo), currentTime);
});

test('it does not allow to set a server time too far from the local time', (t) => {
    t.throws(() => updateServerTime(oneDayAgo));
    t.throws(() => updateServerTime(oneDayAhead));
});
