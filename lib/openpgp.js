let instance; // eslint-disable-line import/no-mutable-exports

export { instance as openpgp };

export const setInstance = (value) => {
    instance = value;
};

export const setConfig = (openpgp) => {
    openpgp.config.s2k_iteration_count_byte = 96;
};
