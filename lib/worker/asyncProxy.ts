import { wrap, Remote, transferHandlers, releaseProxy } from 'comlink';
import type { WorkerApi } from './api';
import { mainThreadTransferHandlers } from './transferHandlers';

export interface WorkerProxyInterface extends Omit<WorkerApi, 'keyStore'> {
    init(workerNumber?: number): void;
    destroy(): Promise<void>;
}

export const WorkerProxy: WorkerProxyInterface = (() => {
    let workerPool: Remote<WorkerApi>[] | null = null;
    let i = -1;

    const initWorker = async () => {
        // Webpack static analyser is not especially powerful at detecting web workers that require bundling,
        // see: https://github.com/webpack/webpack.js.org/issues/4898#issuecomment-823073304.
        // Harcoding the path here is the easiet way to get the worker to be bundled properly.
        const RemoteApi = wrap<typeof WorkerApi>(new Worker(new URL('./worker.ts', import.meta.url)));
        const worker = await new RemoteApi();
        return worker;
    };

    const destroyWorker = async (worker: Remote<WorkerApi>) => {
        await worker?.clearKeyStore();
        worker?.[releaseProxy]();
    }

    const getWorker = (): Remote<WorkerApi>  => {
        if (workerPool == null) throw new Error('Uninitialised worker pool');
        i = (i + 1) % workerPool.length;
        return workerPool[i];
    }

    const getAllWorkers = (): Omit<WorkerApi, 'keyStore'>[] => {
        if (workerPool == null) throw new Error('Uninitialised worker pool');
        return workerPool as unknown as Omit<WorkerApi, 'keyStore'>[];
    }

    return {
        init: async (n = 1) => {
            if (workerPool !== null) {
                throw new Error('worker pool already initialised');
            }
            workerPool = await Promise.all(new Array(n).fill(null).map(() => initWorker()));
            mainThreadTransferHandlers.forEach(({ name, handler }) => transferHandlers.set(name, handler));
        },
        destroy: async () => {
            workerPool && await Promise.all(workerPool.map(destroyWorker));
            workerPool = null;
        },
        // @ts-ignore marked as non-callable, unclear why, might be due to a limitation of type Remote
        encryptMessage: (opts) => getWorker().encryptMessage(opts),
        decryptMessage: (opts) => getWorker().decryptMessage(opts),
        decryptMessageLegacy: (opts) => getWorker().decryptMessageLegacy(opts),
        // @ts-ignore marked as non-callable, unclear why, might be due to a limitation of type Remote
        signMessage: (opts) => getWorker().signMessage(opts),
        // @ts-ignore marked as non-callable, unclear why, might be due to a limitation of type Remote
        verifyMessage: (opts) => getWorker().verifyMessage(opts),
        verifyCleartextMessage: (opts) => getWorker().verifyCleartextMessage(opts),
        processMIME: (opts) => getWorker().processMIME(opts),
        computeHash: (opts) => getWorker().computeHash(opts),

        generateSessionKey: (opts) => getWorker().generateSessionKey(opts),
        generateSessionKeyFromKeyPreferences: (opts) => (
            getWorker().generateSessionKeyFromKeyPreferences(opts)
        ),
        encryptSessionKey: (opts) => getWorker().encryptSessionKey(opts),
        decryptSessionKey: (opts) => getWorker().decryptSessionKey(opts),
        importPrivateKey: async (opts) => {
            const [first, ...rest] = getAllWorkers();
            const result = await first.importPrivateKey(opts);
            await Promise.all(rest.map((worker) => worker.importPrivateKey(opts, result._idx)))
            return result;
        },
        importPublicKey: async (opts) => {
            const [first, ...rest] = getAllWorkers();
            const result = await first.importPublicKey(opts);
            await Promise.all(rest.map((worker) => worker.importPublicKey(opts, result._idx)))
            return result;
        },
        generateKey: async (opts) => {
            const [first, ...rest] = getAllWorkers();
            const keyReference = await first.generateKey(opts);
            const key = await first.exportPrivateKey({ keyReference, passphrase: null });
            await Promise.all(rest.map(
                (worker) => worker.importPrivateKey({ armoredKey: key, passphrase: null }, keyReference._idx))
            )
            return keyReference;
        },
        reformatKey: async (opts) => {
            const [first, ...rest] = getAllWorkers();
            const keyReference = await first.reformatKey(opts);
            const key = await first.exportPrivateKey({ keyReference, passphrase: null });
            await Promise.all(rest.map(
                (worker) => worker.importPrivateKey({ armoredKey: key, passphrase: null }, keyReference._idx))
            )
            return keyReference;
        },
        replaceUserIDs: async (opts) => {
            await Promise.all(getAllWorkers().map((worker) => worker.replaceUserIDs(opts)))
        },
        exportPublicKey: (opts) => getWorker().exportPublicKey(opts),
        exportPrivateKey: (opts) => getWorker().exportPrivateKey(opts),
        clearKeyStore: async () => { await Promise.all(getAllWorkers().map((worker) => worker.clearKeyStore())) },
        clearKey: async (opts) => { await Promise.all(getAllWorkers().map((worker) => worker.clearKey(opts))) },

        isExpiredKey: (opts) => getWorker().isExpiredKey(opts),
        isRevokedKey: (opts) => getWorker().isRevokedKey(opts),
        canKeyEncrypt: (opts) => getWorker().canKeyEncrypt(opts),
        getSHA256Fingerprints: (opts) => getWorker().getSHA256Fingerprints(opts),
        getMessageInfo: (opts) => getWorker().getMessageInfo(opts),
        getKeyInfo: (opts) => getWorker().getKeyInfo(opts),
        getSignatureInfo: (opts) => getWorker().getSignatureInfo(opts),
        getArmoredKeys: (opts) => getWorker().getArmoredKeys(opts),
        getArmoredSignature: (opts) => getWorker().getArmoredSignature(opts),
        getArmoredMessage: (opts) => getWorker().getArmoredMessage(opts),
        serverTime: () => getWorker().serverTime(),
        updateServerTime: (opts) => getWorker().updateServerTime(opts)
    } as WorkerProxyInterface; // casting needed to 'reuse' WorkerApi's parametric types declarations and preserve dynamic inference of
    // the output types based on the input ones.
})();
