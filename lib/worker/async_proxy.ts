import { wrap, Remote } from 'comlink';
import type { WorkerApi } from './worker';

type WorkerInterface = typeof WorkerApi;

let proxy: Remote<WorkerInterface> | null = null;

export const initWorker = (path: string) => {
    if (proxy !== null) {
        throw new Error('worker already initialised');
    }

    proxy = wrap<WorkerInterface>(new Worker(path));
    return proxy;
};

const assertInitialised = (): true => {
    if (proxy == null) throw new Error('Uninitialised worker');
    return true;
};

interface WorkerProxyInterface extends WorkerInterface {
    init(path: string): void;
}

// TODO implement WorkerProxy as class and expose singleton instead? (cleaner to keep the state inside the instance)
// @ts-ignore TODO need to implement all methods
export const WorkerProxy: WorkerProxyInterface = {
    init: (path) => {
        initWorker(path);
    },
    // TODO use Proxy to intercept all methods? to write non-method specific code (might be not possible, depending on key handling architecture we pick)
    // const handler = {
    //   get(obj: any, prop: any) {
    //     if (prop in obj) return obj[prop];
    //     throw new Error(`${prop} is not a function`);
    //   }
    // };
    // proxy = new Proxy(w, handler);
    decryptMessage: (opts) => assertInitialised() && proxy!.decryptMessage(opts)
    // verifyMessage: (opts) => (assertInitialised() && w!.verifyMessage(opts)),
};
