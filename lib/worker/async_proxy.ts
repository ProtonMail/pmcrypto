import { wrap, Remote } from 'comlink';
import type { WorkerApi } from './worker';

type WorkerInterface = typeof WorkerApi;

let worker: Remote<WorkerInterface> | null = null;

export const initWorker = (path: string) => {
    if (worker !== null) {
        throw new Error('worker already initialised');
    }

    worker = wrap<WorkerInterface>(new Worker(path));
    return worker;
};

const assertInitialised = (): true => {
    if (worker == null) throw new Error('Uninitialised worker');
    return true;
};

// TODO all returned types are promises
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
    // @ts-ignore cannot forward type parameters through Comlink.Remote interface
    decryptMessage: (opts) => assertInitialised() && worker!.decryptMessage(opts),
    // @ts-ignore cannot forward type parameters through Comlink.Remote interface, hence the resulting Remote type
    // cannot infer the output signature dynamically based on the input.
    encryptMessage: (opts) => assertInitialised() && worker!.encryptMessage(opts),
    // @ts-ignore cannot forward type parameters through Comlink.Remote interface
    signMessage: (opts) => assertInitialised() && worker!.signMessage(opts),
    // @ts-ignore cannot forward type parameters through Comlink.Remote interface
    verifyMessage: (opts) => (assertInitialised() && worker!.verifyMessage(opts))
};
