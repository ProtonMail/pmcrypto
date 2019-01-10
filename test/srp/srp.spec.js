import { describe, it, before, after } from 'mocha';
import assert from 'assert';

import '../setup';
import * as crypto from '../../lib/crypto';
import { getRandomSrpVerifier, getSrp, perform } from '../../lib/srp/srp';
import { AUTH_RESPONSE, AUTH_RESPONSE_OLD, SERVER_MODULUS, SERVER_MODULUS_FAKE, FAKE_RANDOM } from './srp.data';

describe('srp', () => {
    let original;

    before(() => {
        original = crypto.getRandomValues;
        // eslint-disable-next-line
        crypto.getRandomValues = (buf) => new Uint8Array(FAKE_RANDOM.slice(0, buf.length));
    });

    after(() => {
        // eslint-disable-next-line
        crypto.getRandomValues = original;
    });

    it('should generate verifier', async () => {
        const result = await getRandomSrpVerifier({ Modulus: SERVER_MODULUS, ModulusID: 1 }, { password: '123' });
        assert.deepStrictEqual(result, {
            Version: 4,
            ModulusID: 1,
            Salt: 'SzHkg+YYA/eN1A==',
            Verifier:
                'j2o8z9G+Xm5t07Y6D7rauq3bNi6v0ZqnM1nWuZHS8PgtQOl4Xgh8LjuzulhX1izaOqeIoW221Z/LDVkrUZzxAXwFdi5LfxMN+RHPJCg0Uk5OcigQHsO1xTMuk3hvoIXO7yIXXs2oCqpBwKNfuhMNjcwVlgjyh5ZC4FzhSV2lwlP7KE1me/USAOfq4FbW7KtDtvxX8fk6hezWIz9X8/bcAHwQkHobqOVTCE81Lg+WL7s4sMed72YHwx5p6S/YGm558zrZmeETv6PuS4MRkQ8vPRrIvmzPEQDUiOXCaqfLkGvBFeCbBjNtBM8AlbWcW8XE+gcb/GwWH8cHinzd4ddh4A=='
        });
    });

    it('should reject verify if it is unable to verify identity', async () => {
        const promise = getRandomSrpVerifier({ Modulus: SERVER_MODULUS_FAKE, ModulusID: 1 }, { password: 'hello' });
        await assert.rejects(promise, {
            name: 'Error',
            message: 'Unable to verify server identity'
        });
    });

    it('should generate auth parameters', async () => {
        const result = await getSrp(AUTH_RESPONSE, { password: '123' });
        assert.deepStrictEqual(result, {
            parameters: {
                SRPSession: AUTH_RESPONSE.SRPSession,
                ClientEphemeral:
                    'hlszWWqvmsVvSCYdu0Zvmn/Ow9dSkp91vfhd20yYvd8XTcNixlOloz7lbD+bFR/0mAUYrYuOyYwPDoARAqRiAijQTWSkfOsByeKvmHZN7scxsmMQSp/8BdkIpEcJzUBg762o4L2tgrOFdydtagYRH0++qaJI6iMWlGLVI1atJvEcQ1h9xRylYT8rtL+gqKcYOQbqYgl3mXlHE/9uT8qEBFIP8LthQfIntst1p/dUDYyN4GH5Pb3ajL0qehzrQrDkF5xMmggDXgqflwMtcJTSIB0WcyiG+ls8KhUy8NVwyNhJrbikkzAnhAk4Mq3HmTwtj82BNQzSnDDg1W1lvU1JrA==',
                ClientProof:
                    'iuCo00BHgTVw4808ZU4EIESZhRR4BV8CQoNu8sZJ270hdz2ufRge7/Xpr8hdt08qoNCbDXT0M333d6CeyymLeMcWo7Lr13nGHzmoB5iRSjIjcmROHSD5YkjGAsCejnvoS2Pr0TzGKa32lBwYaxLEuT2162q98N6HpqpYNo2Iuvsd11gx1g9YJiLR7VESiD93NutcZIFta5M0vUQIBvzPI88Ev77d2CoEPyNFZctqcKxeZYsACN+JLq2sw+ME9sIPoSpujn6v6fK9NDSq/tldQmZ/upjFrXMhoLpxwK/daepvHHzfFVv8BbRrXJ2YH9jGPtJPVTUxUqnA2Lu1jBk+nw==',
                TwoFactorCode: undefined
            },
            expectation:
                'ZBdnSNfaP4mgqNoh//ZJgqbsuxBNqSDL+tEPSH7b1wYlamdXNzz1pnp7G1QRBmvSgksdrSQaTZR575hIZ9UbWZNB7qP2opgHKeQATtE69sIgC4ehBF4HZzX2hr/4WC9Q5U0XOdM+1/KWEtVCNjwkmdXJ/3jjRbPH+d2K1yNGAo0iAjTBkIrY5l3FwgDLREKxVZyMyp6CTqzY4XMNY29r/URs+WH+45j4OFOOzhtxE4BoHXTtIPAr6gMTaZ/GsXtDvdBWHZQAYL/lIoQk+BdJhm2riy+OXRwEu0CzMo7JhbbZUbmLDf8gqQFteQnlGdPJD+SEiQC8ebJv4RbbUGnD1g=='
        });
    });

    it('should reject auth if it is unable to verify server', async () => {
        const promise = getSrp({ Modulus: SERVER_MODULUS_FAKE }, { password: '123' });
        await assert.rejects(promise, {
            name: 'Error',
            message: 'Unable to verify server identity'
        });
    });

    it('should reject a request if the server proof is not correct', async () => {
        const requestCb = async () => ({ proof: 'incorrect' });

        const credentials = { password: '123' };
        const promise = perform({ credentials, requestCb, authInfo: AUTH_RESPONSE });

        await assert.rejects(promise, {
            name: 'Error',
            message: 'Unexpected server proof'
        });
    });

    it('should resolve a request if the server proof is correct', async () => {
        const credentials = { password: '123' };
        const { expectation } = await getSrp(AUTH_RESPONSE, credentials);
        const requestCb = async () => ({ proof: expectation, result: 'foo' });
        const { result } = await perform({ credentials, requestCb, authInfo: AUTH_RESPONSE });
        assert.strictEqual(result, 'foo');
    });

    it('should perform an auth request with an old auth version', async () => {
        const credentials = { username: 'test100', password: '123' };

        const requestCb = async () => {
            return {
                proof:
                    'b/ldj2+DZDoU8AoROROaHmR3ACaZAyOLDd3WkbHnghiKSvKHe2LSYTEmWvyNduUkytTzN7OFVcl60t1JF364omODE3bsekCNVz/DJzeoOnN9WR4N1EwYo/LVjjnv97c2aA0JBpZvc6yNiChhiEk/C63DKs0DFuxdB8IvNxJpIePKRb73P4HODf3hNsVdBusKmWHTHYZQWrnt8NpRWcEreyZ6iQLyWskbjNXmTCtbXb/F7kWZfegriP09UxZHqkFkxiawded3wd4x4thpLz1BGZnzhr8N6Ko/0FmxVlZMucWqHYwlkUQvbLYwPBxPMv05L2nLvjMFSPK1r4cepj0CYQ=='
            };
        };

        const { authVersion } = await perform({ credentials, requestCb, authInfo: AUTH_RESPONSE_OLD });
        assert.strictEqual(authVersion, 2);
    });

    it('should perform an auth request with an old auth version and fall back', async () => {
        const credentials = { username: 'test100', password: '123' };

        let count = 0;

        const requestCb = async () => {
            if (!count) {
                count++;
                const e = new Error();
                e.incorrect = true;
                throw e;
            }
            return {
                proof:
                    '0jxGds6roPxUmdLIsSTdoRjlHLQTfLUgjTlyjCIR9n6siNgnlyh90hmqg/3pNAT6FBlFk/0411cEPMip4lXbSeUz+x6/GC5ZWzoZs1MZYM7gRfpyzXP3YYUok+7LWIMjuP71AHfIW1Gois3Op2o+LJEBC4/ZA7LPqhHg4RpxkTNEiy5QhI8sc/yDZsdabblaq/D/+APhJYfaG7Rol3uyJZDez5k5uu5h61woM6CQ/3zOPLgaUw5JU8FCgYkQurZoA0a0C4MsDMC8bfXUQ8cLCdygPR3pAt2ycquU3y6tN3MsMcCtm3ivRky93Vip6BI1CIZbs7aF1Ygd5KxDRgUjsA=='
            };
        };

        const fallbackCb = ({ fallbackAuthVersion }) => {
            return perform({
                credentials,
                requestCb,
                fallbackCb,
                authInfo: AUTH_RESPONSE_OLD,
                fallbackAuthVersion
            });
        };

        const { authVersion } = await fallbackCb({});
        assert.strictEqual(authVersion, 0);
    });
});
