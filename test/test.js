const chai = require('chai');
// chai.use(require('chai-as-promised'));
const { expect } = chai;

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
