import { config } from 'openpgp';

export const setConfig = () => {
    config.s2k_iteration_count_byte = 96;
};
