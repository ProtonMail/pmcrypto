import { Argon2S2K, Config, config as defaultConfig } from '../openpgp';
import { ARGON2_PARAMS } from '../constants';

type Argon2Params = Config['s2kArgon2Params'] & {
    tagLength: number
};

export interface Argon2Options {
    password: string,
    salt: Uint8Array,
    /** see https://www.rfc-editor.org/rfc/rfc9106.html#name-parameter-choice */
    params: Argon2Params
}

// We manually reload the module if no memory-heavy (128MB+) argon2 computation has been requested in a while,
// to deallocate the memory.
// This is better than reloading the module every time (automatically done if the memory exceeds `Argon2S2K.ARGON2_WASM_MEMORY_THRESHOLD_RELOAD`),
// as doing so comes with a performance hit.
const SECOND = 1000;
const TimeoutHandler = {
    id: undefined,
    cancelReloadingTimeout: (memoryExponent: number) => (
        memoryExponent > ARGON2_PARAMS.MINIMUM.memoryExponent && clearTimeout(TimeoutHandler.id)
    ),
    setupReloadingTimeout: (memoryExponent: number) => {
        const shouldReloadAfterTimeout = memoryExponent > ARGON2_PARAMS.MINIMUM.memoryExponent &&
            memoryExponent < Argon2S2K.ARGON2_WASM_MEMORY_THRESHOLD_RELOAD;
        // @ts-ignore NodeJS.Timeout typedef interfering
        TimeoutHandler.id = shouldReloadAfterTimeout ?
            setTimeout(
                () => Argon2S2K.reloadWasmModule(),
                10 * SECOND
            ) as any as number
            : undefined;
    }
};

export async function argon2({ password, salt, params = ARGON2_PARAMS.RECOMMENDED }: Argon2Options) {
    TimeoutHandler.cancelReloadingTimeout(params.memoryExponent);

    const s2k = new Argon2S2K({ ...defaultConfig, s2kArgon2Params: params });
    s2k.salt = salt;
    const result = await s2k.produceKey(password, params.tagLength);

    TimeoutHandler.setupReloadingTimeout(params.memoryExponent);
    return result;
}
