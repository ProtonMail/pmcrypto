let lastServerTime = null;

export const serverTime = () => lastServerTime || new Date();
export const updateServerTime = (serverDate) => {
    if (serverDate > lastServerTime) {
        lastServerTime = serverDate;
    }
    return lastServerTime;
};
