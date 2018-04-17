module.exports = (performance = Date) => {

    let lastServerTime = null;
    let clientTime = null;

    function serverTime() {
        if (lastServerTime !== null) {
            return new Date(+lastServerTime + (performance.now() - clientTime));
        }
        return new Date();
    }

    function updateServerTime(serverDate) {
        lastServerTime = serverDate;
        clientTime = performance.now();
    }

    return { serverTime, updateServerTime }
};
