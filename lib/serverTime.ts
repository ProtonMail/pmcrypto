let lastServerTime: Date | null = null;

export const serverTime = () => lastServerTime || new Date();
export const updateServerTime = (serverDate: Date) => {
    if (lastServerTime === null || serverDate > lastServerTime) {
        lastServerTime = serverDate;
    }
    return lastServerTime;
};
