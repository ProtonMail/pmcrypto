import { expect, use as chaiUse } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import { initWorker } from '../../lib/worker/async_proxy';

chaiUse(chaiAsPromised);

describe('', () => {
  it('yolo', async () => {
    const obj = initWorker('/dist/worker.js');
    // console.log(obj)
    expect(await obj.inc()).to.equal(1)
    await obj.generateKey({})
  })
});
