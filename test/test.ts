import { expect } from 'chai';
// chai.use(require('chai-as-promised'));
// const { expect } = chai;
// require('./helper');
import { createMessage, init } from '../lib';
import { config, setConfig } from '../lib/openpgp';

before(init)

it('it sets the correct configuration on openpgp', async () => {
    expect(config.s2kIterationCountByte).to.eq(96);
});

describe('Array', () => {
    describe('#indexOf()', () => {
        it('should return -1 when the value is not present', () => {
            expect([1, 2, 3].indexOf(4)).to.equal(-1);
        });

        it('should return -1 when the value is present', () => {
            expect([1, 2, 3].indexOf(4)).to.equal(-1);
        });
    });
});
