import { expose, transferHandlers } from 'comlink';
import { workerTransferHandlers } from './transferHandlers';
import { Api as WorkerApi } from './api';
import { init as initPmcrypto } from '../pmcrypto';

workerTransferHandlers.forEach(
    ({ name, handler }) => transferHandlers.set(name, handler)
);

initPmcrypto();

expose(WorkerApi);
