import { wrap, Remote, transferHandlers, releaseProxy } from 'comlink';
import type { WorkerApi } from './api';
import { mainThreadTransferHandlers } from './transferHandlers';

const assertInitialised = (value: Remote<WorkerApi> | null): value is Remote<WorkerApi> => {
    if (value == null) throw new Error('Uninitialised worker');
    return true;
};

export interface WorkerProxyInterface extends Omit<WorkerApi, 'keyStore'> {
    init(): void;
    destroy(): Promise<void>;
}

export const WorkerProxy: WorkerProxyInterface = (() => {
    let worker: Remote<WorkerApi> | null = null;

    const initWorker = async () => {
        if (worker !== null) {
            throw new Error('worker already initialised');
        }

        // Webpack static analyser is not especially powerful at detecting web workers that require bundling,
        // see: https://github.com/webpack/webpack.js.org/issues/4898#issuecomment-823073304.
        // Harcoding the path here is the easiet way to get the worker to be bundled properly.
        const RemoteApi = wrap<typeof WorkerApi>(new Worker(new URL('./worker.ts', import.meta.url)));
        worker = await new RemoteApi();
    };

    const destroyWorker = async () => {
        await worker?.clearKeyStore();
        worker?.[releaseProxy]();
        worker = null;
    }

    return {
        init: async () => {
            await initWorker();
            mainThreadTransferHandlers.forEach(({ name, handler }) => transferHandlers.set(name, handler));
        },
        destroy: destroyWorker,
        // @ts-ignore marked as non-callable, unclear why, might be due to a limitation of type Remote
        encryptMessage: (opts) => assertInitialised(worker) && worker.encryptMessage(opts),
        decryptMessage: (opts) => assertInitialised(worker) && worker.decryptMessage(opts),
        decryptMessageLegacy: (opts) => assertInitialised(worker) && worker.decryptMessageLegacy(opts),
        // @ts-ignore marked as non-callable, unclear why, might be due to a limitation of type Remote
        signMessage: (opts) => assertInitialised(worker) && worker.signMessage(opts),
        // @ts-ignore marked as non-callable, unclear why, might be due to a limitation of type Remote
        verifyMessage: (opts) => assertInitialised(worker) && worker.verifyMessage(opts),
        processMIME: (opts) => assertInitialised(worker) && worker.processMIME(opts),

        generateSessionKey: (opts) => assertInitialised(worker) && worker.generateSessionKey(opts),
        generateSessionKeyFromKeyPreferences: (opts) => (
            assertInitialised(worker) && worker.generateSessionKeyFromKeyPreferences(opts)
        ),
        encryptSessionKey: (opts) => assertInitialised(worker) && worker.encryptSessionKey(opts),
        decryptSessionKey: (opts) => assertInitialised(worker) && worker.decryptSessionKey(opts),

        importPrivateKey: (opts) => assertInitialised(worker) && worker.importPrivateKey(opts),
        importPublicKey: (opts) => assertInitialised(worker) && worker.importPublicKey(opts),
        generateKey: (opts) => assertInitialised(worker) && worker.generateKey(opts),
        reformatKey: (opts) => assertInitialised(worker) && worker.reformatKey(opts),
        exportPublicKey: (opts) => assertInitialised(worker) && worker.exportPublicKey(opts),
        exportPrivateKey: (opts) => assertInitialised(worker) && worker.exportPrivateKey(opts),
        clearKeyStore: () => assertInitialised(worker) && worker.clearKeyStore(),
        clearKey: (opts) => assertInitialised(worker) && worker.clearKey(opts),

        isExpiredKey: (opts) => assertInitialised(worker) && worker.isExpiredKey(opts),
        isRevokedKey: (opts) => assertInitialised(worker) && worker.isRevokedKey(opts),
        canKeyEncrypt: (opts) => assertInitialised(worker) && worker.canKeyEncrypt(opts),
        getMessageInfo: (opts) => assertInitialised(worker) && worker.getMessageInfo(opts),
        getSignatureInfo: (opts) => assertInitialised(worker) && worker.getSignatureInfo(opts),
        getArmoredSignature: (opts) => assertInitialised(worker) && worker.getArmoredSignature(opts),
        serverTime: () => assertInitialised(worker) && worker.serverTime(),
        updateServerTime: (opts) => assertInitialised(worker) && worker.updateServerTime(opts)
    } as WorkerProxyInterface; // casting needed to 'reuse' WorkerApi's parametric types declarations and preserve dynamic inference of
    // the output types based on the input ones.
})();
