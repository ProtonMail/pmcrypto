import { describe, it, before, after } from 'mocha';
import assert from 'assert';

import '../setup';
import * as crypto from '../../lib/crypto';
import { randomVerifier, auth } from '../../lib/srp/srp';
import { AUTH_RESPONSE, SERVER_MODULUS, SERVER_MODULUS_FAKE, FAKE_RANDOM } from './srp.data';

describe('srp', () => {
    let original;

    before(() => {
        original = crypto.getRandomValues;
        crypto.getRandomValues = (buf) => new Uint8Array(FAKE_RANDOM.slice(0, buf.length));
    });

    after(() => {
        crypto.getRandomValues = original;
    });

    it('should generate verifier', async () => {
        const result = await randomVerifier(
            { Modulus: SERVER_MODULUS, ModulusID: 1 },
            {
                password: '123',
                version: 4
            }
        );
        assert.deepStrictEqual(result, {
            Version: 4,
            ModulusID: 1,
            Salt: 'SzHkg+YYA/eN1A==',
            Verifier:
                'j2o8z9G+Xm5t07Y6D7rauq3bNi6v0ZqnM1nWuZHS8PgtQOl4Xgh8LjuzulhX1izaOqeIoW221Z/LDVkrUZzxAXwFdi5LfxMN+RHPJCg0Uk5OcigQHsO1xTMuk3hvoIXO7yIXXs2oCqpBwKNfuhMNjcwVlgjyh5ZC4FzhSV2lwlP7KE1me/USAOfq4FbW7KtDtvxX8fk6hezWIz9X8/bcAHwQkHobqOVTCE81Lg+WL7s4sMed72YHwx5p6S/YGm558zrZmeETv6PuS4MRkQ8vPRrIvmzPEQDUiOXCaqfLkGvBFeCbBjNtBM8AlbWcW8XE+gcb/GwWH8cHinzd4ddh4A=='
        });
    });

    it('should reject verify if it is unable to verify identity', async () => {
        const promise = randomVerifier(
            { Modulus: SERVER_MODULUS_FAKE, ModulusID: 1 },
            {
                password: 'hello',
                version: 4
            }
        );
        await assert.rejects(promise, {
            name: 'Error',
            message: 'Unable to verify server identity'
        });
    });

    it('should generate auth parameters', async () => {
        const result = await auth(AUTH_RESPONSE, { password: '123' }, 2);
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
        const promise = auth({ Modulus: SERVER_MODULUS_FAKE }, { password: '123' }, 2);
        await assert.rejects(promise, {
            name: 'Error',
            message: 'Unable to verify server identity'
        });
    });
});
