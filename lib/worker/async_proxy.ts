import { wrap } from 'comlink';
import type { Api } from './api';

export const initWorker = (path: string) => wrap<typeof Api>(
  new Worker(path));
