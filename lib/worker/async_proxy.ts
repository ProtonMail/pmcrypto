import { wrap } from 'comlink';
import type { WorkerApi } from './worker';

export const initWorker = (path: string) => wrap<typeof WorkerApi>(
  new Worker(path));

// need this to transfer the data
