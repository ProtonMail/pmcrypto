import { BigNumber, Modulus } from 'asmcrypto.js/asmcrypto.all.es8';

import { openpgp } from '../openpgp';
import { cleanUsername, hashPassword } from '../passwords';
import { arrayToBinaryString, binaryStringToArray, decodeBase64, encodeBase64 } from '../utils';
import { getRandomValues } from '../crypto';
import { fromBN, generateClientSecret, verifyAndGetModulus, srpHasher, toBN } from './utils';
import { AUTH_VERSION, AUTH_FALLBACK_VERSION, SRP_LEN } from '../constants';

const ZERO_BN = BigNumber.fromNumber(0);
const ONE_BN = BigNumber.fromNumber(1);
const TWO_BN = BigNumber.fromNumber(2);

/**
 * Get the client secret. Loops until it finds a safe value.
 * @param {Number} len
 * @return {BigNumber}
 */
const getClientSecret = (len) => {
    const comparator = BigNumber.fromNumber(len * 2);

    while (true) {
        const clientSecret = generateClientSecret(len);

        if (clientSecret.compare(comparator) <= 0) {
            continue;
        }

        return clientSecret;
    }
};

/**
 * Generate parameters.
 * @param {Object} params
 * @param {Number} params.len
 * @param {BigNumber} params.generator
 * @param {BigNumber} params.modulus
 * @param {Uint8Array} params.serverEphemeralArray
 * @return {Promise<{clientSecret, clientEphemeral, scramblingParam}>}
 */
const generateParameters = async ({ len, generator, modulus, serverEphemeralArray }) => {
    const clientSecret = getClientSecret(len);
    const clientEphemeral = modulus.power(generator, clientSecret);
    const clientEphemeralArray = fromBN(len, clientEphemeral);

    const clientServerHash = await srpHasher(
        openpgp.util.concatUint8Array([clientEphemeralArray, serverEphemeralArray])
    );
    const scramblingParam = toBN(clientServerHash);

    return {
        clientSecret,
        clientEphemeral,
        scramblingParam
    };
};

/**
 * Get parameters. Loops until it finds safe values.
 * @param {Number} len
 * @param {BigNumber} generator
 * @param {BigNumber} modulus
 * @param {Uint8Array} serverEphemeralArray
 * @return {Promise<{clientSecret, clientEphemeral, scramblingParam}>}
 */
const getParameters = async ({ len, generator, modulus, serverEphemeralArray }) => {
    while (true) {
        // eslint-disable-next-line no-await-in-loop
        const { clientSecret, clientEphemeral, scramblingParam } = await generateParameters({
            len,
            generator,
            modulus,
            serverEphemeralArray
        });

        if (scramblingParam.compare(ZERO_BN) === 0) {
            continue;
        }

        return {
            clientSecret,
            clientEphemeral,
            scramblingParam
        };
    }
};

/**
 * @param {Object} params
 * @param {Number} params.len - Size of the proof (bytes length)
 * @param {Uint8Array} params.modulusArray
 * @param {Uint8Array} params.hashedPasswordArray
 * @param {Uint8Array} params.serverEphemeralArray
 * @return {Promise}
 */
export const generateProofs = async ({ len, modulusArray, hashedPasswordArray, serverEphemeralArray }) => {
    const modulusBn = toBN(modulusArray);
    if (modulusBn.bitLength !== len) {
        throw new Error('SRP modulus has incorrect size');
    }

    const generator = TWO_BN;

    const hashedArray = await srpHasher(openpgp.util.concatUint8Array([fromBN(len, generator), modulusArray]));

    const multiplierBn = toBN(hashedArray);
    const serverEphemeral = toBN(serverEphemeralArray);
    const hashedPassword = toBN(hashedPasswordArray);

    const modulus = new Modulus(modulusBn);
    const modulusMinusOne = modulus.subtract(ONE_BN);
    const multiplierReduced = modulus.reduce(multiplierBn);

    if (multiplierReduced.compare(ONE_BN) <= 0 || multiplierReduced.compare(modulusMinusOne) >= 0) {
        throw new Error('SRP multiplier is out of bounds');
    }

    if (generator.compare(ONE_BN) <= 0 || generator.compare(modulusMinusOne) >= 0) {
        throw new Error('SRP generator is out of bounds');
    }

    if (serverEphemeral.compare(ONE_BN) <= 0 || serverEphemeral.compare(modulusMinusOne) >= 0) {
        throw new Error('SRP server ephemeral is out of bounds');
    }

    const { clientSecret, clientEphemeral, scramblingParam } = await getParameters({
        len,
        generator,
        modulus,
        serverEphemeralArray
    });

    let subtracted = serverEphemeral.subtract(
        modulus.reduce(modulus.power(generator, hashedPassword).multiply(multiplierReduced))
    );

    if (subtracted.compare(ZERO_BN) < 0) {
        subtracted = subtracted.add(modulus);
    }

    const exponent = scramblingParam
        .multiply(hashedPassword)
        .add(clientSecret)
        .divide(modulus.subtract(ONE_BN)).remainder;
    const sharedSession = modulus.power(subtracted, exponent);

    const clientProof = await srpHasher(
        openpgp.util.concatUint8Array([
            fromBN(len, clientEphemeral),
            fromBN(len, serverEphemeral),
            fromBN(len, sharedSession)
        ])
    );
    const serverProof = await srpHasher(
        openpgp.util.concatUint8Array([fromBN(len, clientEphemeral), clientProof, fromBN(len, sharedSession)])
    );

    return {
        ClientEphemeral: fromBN(len, clientEphemeral),
        ClientProof: clientProof,
        ExpectedServerProof: serverProof
    };
};

/**
 * Validate username for old auth versions.
 * @param {Number} authVersion
 * @param {String} username
 * @param {String} usernameApi
 * @return {boolean}
 */
const checkUsername = (authVersion, username, usernameApi) => {
    if (authVersion === 2) {
        if (cleanUsername(username) !== cleanUsername(usernameApi)) {
            return false;
        }
    }

    if (authVersion <= 1) {
        if (username.toLowerCase() !== usernameApi.toLowerCase()) {
            return false;
        }
    }

    return true;
};

/**
 * @param {Object} data - Auth info from the API
 * @param {String} data.SRPSession - Hex encoded session key
 * @param {String} data.Modulus - Base 64 encoded server modulus as a pgp signed message
 * @param {String} data.ServerEphemeral - Base64 encoded server ephemeral
 * @param {String} [data.Username] - The user name
 * @param {String} [data.Salt] - Base64 encoded salt
 * @param {Object} credentials - Credentials entered by the user
 * @param {String} [credentials.username] - Username entered
 * @param {String} credentials.password - Password code entered
 * @param {String} [credentials.totp] - Two factor code entered
 * @param {Number} [authVersion] - The auth version
 * @return {Promise}
 */
export const getSrp = async (
    { SRPSession, Modulus, ServerEphemeral, Username, Salt },
    { username, password, totp },
    authVersion = AUTH_VERSION
) => {
    const modulusArray = await verifyAndGetModulus(Modulus);
    const serverEphemeralArray = binaryStringToArray(decodeBase64(ServerEphemeral));

    if (!checkUsername(authVersion, username, Username)) {
        throw new Error('Please login with just your ProtonMail username (without @protonmail.com or @protonmail.ch).');
    }

    const hashedPasswordArray = await hashPassword({
        version: authVersion,
        password,
        salt: authVersion < 3 ? undefined : decodeBase64(Salt),
        username: authVersion < 3 ? Username : undefined,
        modulus: modulusArray
    });

    const { ClientEphemeral, ClientProof, ExpectedServerProof } = await generateProofs({
        len: SRP_LEN,
        modulusArray,
        hashedPasswordArray,
        serverEphemeralArray
    });

    return {
        parameters: {
            SRPSession,
            ClientEphemeral: encodeBase64(arrayToBinaryString(ClientEphemeral)),
            ClientProof: encodeBase64(arrayToBinaryString(ClientProof)),
            TwoFactorCode: totp
        },
        expectation: encodeBase64(arrayToBinaryString(ExpectedServerProof))
    };
};

/**
 * @param {Number} len
 * @param {Uint8Array} hashedPassword
 * @param {Uint8Array} modulus
 * @return {Uint8Array}
 */
const generateVerifier = (len, hashedPassword, modulus) => {
    const generator = TWO_BN;

    const modulusBn = new Modulus(toBN(modulus));
    const hashedPasswordBn = toBN(hashedPassword);

    const verifier = modulusBn.power(generator, hashedPasswordBn);
    return fromBN(len, verifier);
};

/**
 * @param {Object} data - Modulus data from the API
 * @param {String} data.Modulus - Base 64 encoded server modulus as a pgp signed message
 * @param {Number} data.ModulusID - The id of the modulus
 * @param {Object} credentials - Credentials data as entered by the user
 * @param {String} [credentials.username] - Not needed if the auth version is >= 3
 * @param {String} credentials.password
 * @param {Number} [version] - Auth version
 * @return {Promise}
 */
export const getRandomSrpVerifier = async ({ Modulus, ModulusID }, { username, password }, version = AUTH_VERSION) => {
    const modulus = await verifyAndGetModulus(Modulus);
    const salt = arrayToBinaryString(getRandomValues(new Uint8Array(10)));
    const hashedPassword = await hashPassword({
        version,
        username,
        password,
        salt,
        modulus
    });

    const verifier = generateVerifier(SRP_LEN, hashedPassword, modulus);

    return {
        Version: version,
        ModulusID,
        Salt: encodeBase64(salt),
        Verifier: encodeBase64(arrayToBinaryString(verifier))
    };
};

/**
 * Get the fallback auth version.
 * @param {Object} credentials
 * @param {String} credentials.username
 * @param {number} fallbackAuthVersion
 * @return {number}
 */
export const getFallbackAuthVersion = (credentials, fallbackAuthVersion) => {
    const { username = '' } = credentials;

    if (fallbackAuthVersion === 2 && cleanUsername(username) !== username.toLowerCase()) {
        return 1;
    }

    if (fallbackAuthVersion === 1 || fallbackAuthVersion === 2) {
        return 0;
    }

    return -1;
};

/**
 * Perform an srp call.
 * If it succeeds, it will resolve to an object containing `result` returned from `requestCb`,
 * and `authVersion` as the auth version used for the successful request.
 * If it fails, it can either throw the `error` thrown by `requestCb`, or it can
 * throw custom errors from the SRP verification process.
 * @param {Object} credentials
 * @param {String} credentials.username
 * @param {String} credentials.password
 * @param {String} credentials.totp
 * @param {Function} requestCb - The request to call.
 * It must return a promise.
 * If it throws, the error should contain a key `incorrect` if the API responded with incorrect credentials.
 * If it resolves, it must resolve to an object with result and proof where result is the result of the response
 * and proof is the server proof received from the API.
 * This is to enable the fallback behavior without knowing the internals of the request.
 * @param {Function} fallbackCb - If the fallback cb is called, it must call `perform` with the
 * `fallbackAuthVersion` received as a key in the argument object to have proper fallback behavior.
 * @param {Object} authInfo - Result from the info API call
 * @param {Number} [fallbackAuthVersion] - The auth version to fall back to
 * @return {Promise<Object>}
 */
export const perform = async ({
    credentials,
    requestCb,
    fallbackCb,
    authInfo,
    fallbackAuthVersion = AUTH_FALLBACK_VERSION
}) => {
    const { Version, ...rest } = authInfo;
    const shouldFallback = Version === 0;
    const authVersion = shouldFallback ? fallbackAuthVersion : Version;

    const { parameters, expectation } = await getSrp(rest, credentials, authVersion);

    try {
        const { result, proof } = await requestCb(parameters);

        if (proof !== expectation) {
            throw new Error('Unexpected server proof');
        }

        return {
            result,
            authVersion
        };
    } catch (e) {
        if (e.incorrect && shouldFallback) {
            const nextFallbackAuthVersion = getFallbackAuthVersion(credentials, fallbackAuthVersion);
            if (nextFallbackAuthVersion !== -1) {
                return fallbackCb({ fallbackAuthVersion: nextFallbackAuthVersion });
            }
        }

        throw e;
    }
};
