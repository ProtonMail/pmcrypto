import { wrap, Remote, transferHandlers, releaseProxy } from 'comlink';
import type { WorkerApi } from './api';
import { mainThreadTransferHandlers } from './transferHandlers';

let worker: Remote<WorkerApi> | null = null;

const initWorker = async () => {
    if (worker !== null) {
        throw new Error('worker already initialised');
    }

    // Webpack static analyser is not especially powerful at detecting web workers that require bundling,
    // see: https://github.com/webpack/webpack.js.org/issues/4898#issuecomment-823073304.
    // Harcoding the path here is the easiet way to get the worker to be bundled properly.
    const RemoteApi = wrap<typeof WorkerApi>(new Worker(new URL('./worker.ts', import.meta.url)));
    worker = await new RemoteApi()
    return worker;
};

const destroyWorker = async () => {
    await worker?.clearKeyStore();
    worker?.[releaseProxy]();
}

const assertInitialised = (): true => {
    if (worker == null) throw new Error('Uninitialised worker');
    return true;
};

// TODO all returned types are promises
interface WorkerProxyInterface extends WorkerApi {
    init(): void;
    destroy(): Promise<void>;
}

// TODO implement WorkerProxy as class and expose singleton instead? (cleaner to keep the state inside the instance)
export const WorkerProxy: WorkerProxyInterface = {
    init: async () => {
        await initWorker();
        mainThreadTransferHandlers.forEach(({ name, handler }) => transferHandlers.set(name, handler));
    },
    destroy: destroyWorker,
    // @ts-ignore cannot forward type parameters through Comlink.Remote interface, hence the resulting Remote type
    // cannot infer the output signature dynamically based on the input.
    encryptMessage: (opts) => assertInitialised() && worker!.encryptMessage(opts),
    // @ts-ignore cannot forward type parameters through Comlink.Remote interface
    decryptMessage: (opts) => assertInitialised() && worker!.decryptMessage(opts),
    // @ts-ignore cannot forward type parameters through Comlink.Remote interface
    decryptMessageLegacy: (opts) => assertInitialised() && worker!.decryptMessageLegacy(opts),
    // @ts-ignore cannot forward type parameters through Comlink.Remote interface
    signMessage: (opts) => assertInitialised() && worker!.signMessage(opts),
    // @ts-ignore cannot forward type parameters through Comlink.Remote interface
    verifyMessage: (opts) => assertInitialised() && worker!.verifyMessage(opts),

    generateSessionKey: (opts) => assertInitialised() && worker!.generateSessionKey(opts),
    generateSessionKeyFromKeyPreferences: (opts) => (
        assertInitialised() && worker!.generateSessionKeyFromKeyPreferences(opts)
    ),
    // @ts-ignore cannot forward type parameters through Comlink.Remote interface
    encryptSessionKey: (opts) => assertInitialised() && worker!.encryptSessionKey(opts),
    decryptSessionKey: (opts) => assertInitialised() && worker!.decryptSessionKey(opts),

    importPrivateKey: (opts) => assertInitialised() && worker!.importPrivateKey(opts),
    importPublicKey: (opts) => assertInitialised() && worker!.importPublicKey(opts),
    generateKey: (opts) => assertInitialised() && worker!.generateKey(opts),
    // @ts-ignore cannot forward type parameters through Comlink.Remote interface
    exportPublicKey: (opts) => assertInitialised() && worker!.exportPublicKey(opts),
    // @ts-ignore cannot forward type parameters through Comlink.Remote interface
    exportPrivateKey: (opts) => assertInitialised() && worker!.exportPrivateKey(opts),
    clearKeyStore: () => assertInitialised() && worker!.clearKeyStore(),
    clearKey: (opts) => assertInitialised() && worker!.clearKey(opts),
    serverTime: () => assertInitialised() && worker!.serverTime(),
    updateServerTime: (opts) => assertInitialised() && worker!.updateServerTime(opts)
};
