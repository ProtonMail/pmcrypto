/* eslint-disable @typescript-eslint/indent */
import type {
    Data,
    VerifyOptions,
    VerifyMessageResult as openpgp_VerifyMessageResult,
    CleartextMessage,
    Signature as OpenPGPSignature
} from 'openpgp/lightweight';
import { VERIFICATION_STATUS } from '../constants';

// Streaming not supported when verifying detached signatures
export interface VerifyOptionsPmcrypto<T extends Data> extends Omit<VerifyOptions, 'message'> {
    textData?: T extends string ? T : never;
    binaryData?: T extends Uint8Array ? T : never;
    stripTrailingSpaces?: T extends string ? boolean : never;
}

export interface VerifyMessageResult<DataType extends openpgp_VerifyMessageResult['data'] = Data> {
    data: DataType;
    verified: VERIFICATION_STATUS;
    signatures: OpenPGPSignature[];
    signatureTimestamp: Date | null;
    errors?: Error[];
}
export function verifyMessage<DataType extends Data, FormatType extends VerifyOptions['format'] = 'utf8'>(
    options: VerifyOptionsPmcrypto<DataType> & { format?: FormatType }
): Promise<
    FormatType extends 'utf8' ?
        VerifyMessageResult<string> :
    FormatType extends 'binary' ?
        VerifyMessageResult<Uint8Array> :
    never
>;

export interface VerifyCleartextOptionsPmcrypto extends Omit<VerifyOptions, 'message' | 'signature' | 'format'> {
    cleartextMessage: CleartextMessage
}
// Cleartext message data is always of utf8 format
export function verifyCleartextMessage(
  options: VerifyCleartextOptionsPmcrypto
): Promise<VerifyMessageResult<string>>;
