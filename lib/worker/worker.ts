/* eslint-disable no-underscore-dangle */
import { expose, transferHandlers } from 'comlink';
import { workerTransferHandlers } from './transferHandlers';
import { WorkerApi } from './api';

workerTransferHandlers.forEach(
    ({ name, handler }) => transferHandlers.set(name, handler)
);

expose(WorkerApi);
