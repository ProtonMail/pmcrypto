const MILLISECONDS_24_HOURS = 24 * 3600 * 1000;
let lastServerTime = null;

export const serverTime = () => lastServerTime || new Date();
export const updateServerTime = (serverDate) => {
    const localTime = new Date();
    const timeDifference = Math.abs(serverDate - localTime);
    if (timeDifference > MILLISECONDS_24_HOURS) {
        throw new Error('Server time is too far off from local time');
    }
    if (serverDate > lastServerTime) {
        lastServerTime = serverDate;
    }
    return lastServerTime;
};
