const MILLISECONDS_24_HOURS = 24 * 3600 * 1000;
let lastServerTime = null;

export const serverTime = () => lastServerTime || new Date();
export const updateServerTime = (serverDate) => {
    const localTime = new Date();
    const timeDifference = Math.abs(serverDate - localTime);
    if (serverDate > lastServerTime && timeDifference < MILLISECONDS_24_HOURS) {
        lastServerTime = serverDate;
    }
    return lastServerTime;
};
