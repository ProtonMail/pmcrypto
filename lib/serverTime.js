let lastServerTime = null;

export const serverTime = () => lastServerTime || new Date();
export const updateServerTime = (serverDate) => (lastServerTime = serverDate);
