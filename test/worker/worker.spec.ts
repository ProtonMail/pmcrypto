import { expect, use as chaiUse } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import { VERIFICATION_STATUS, WorkerProxy } from '../../lib';
import { stringToUtf8Array } from '../../lib/pmcrypto';

chaiUse(chaiAsPromised);
const workerPath = '/dist/worker.js';

before(() => {
  WorkerProxy.init(workerPath);
})

describe('WorkerAPI and Proxy Integration', () => {
  it('init - should throw if already initialised', async () => {
    expect(() => WorkerProxy.init(workerPath)).to.throw(/already initialised/);
  })

  it('decryptMessage - should decrypt message with correct password', async () => {
    const armoredMessage = `-----BEGIN PGP MESSAGE-----

wy4ECQMIxybp91nMWQIAa8pGeuXzR6zIs+uE6bUywPM4GKG8sve4lJoxGbVS
/xN10jwBEsZQGe7OTWqxJ9NNtv6X6qFEkvABp4PD3xvi34lo2WUAaUN2wb0g
tBiO7HKQxoGj3FnUTJnI52Y0pIg=
=HJfc
-----END PGP MESSAGE-----`
    const decryptionResult = await WorkerProxy.decryptMessage({
      armoredMessage,
      passwords: 'password'
    });
    expect(decryptionResult.data).to.equal('hello world');
    expect(decryptionResult.signatures).to.have.length(0);
    expect(decryptionResult.errors).to.not.exist;
    expect(decryptionResult.verified).to.equal(VERIFICATION_STATUS.NOT_SIGNED)

    const decryptWithWrongPassword = WorkerProxy.decryptMessage({
        armoredMessage,
        passwords: 'wrong password'
    });
    await expect(decryptWithWrongPassword).to.be.rejectedWith(/Error decrypting message/);
  });

  it('decryptMessage - message with signature', async () => {
    const messageWithSignature = `-----BEGIN PGP MESSAGE-----

wy4ECQMIUxTg50RvG9EAMkSwKLgTqzpEMlGv1+IKf52HmId83iK4kku8nBzR
FxcD0sACAc9hM9NVeaAhGQdsTqt9zRcRmMRhyWqoAsR0+uZukqPxGZfOw0+6
ouguW3wrVd+/niaHPaDs87sATldw5KK5WI9xcR+mBid4Bq7hugXNcZDMa8qN
gqM8VJm8262cvZAtjwbH50TjBNl+q/YN7DDr+BXd6gRzrvMM+hl5UwYiiYfW
qXGo4MRQBT+B41Yjh/2rUdlCmWoRw2OGWzQTmTspNm4EEolrT6jdYQMxn9IZ
GzGRkb+Rzb42pnKcuihith40374=
=ccav
-----END PGP MESSAGE-----
`;
    const decryptionResult = await WorkerProxy.decryptMessage({
      armoredMessage: messageWithSignature,
      passwords: 'password'
    });

    expect(decryptionResult.data).to.equal('hello world');
    expect(decryptionResult.signatures).to.have.length(1);
    expect(decryptionResult.errors).to.have.length(1);
    expect(decryptionResult.errors![0]).instanceOf(Error); // Errors should be automatically reconstructed by comlink
    expect(decryptionResult.errors![0]).to.match(/Could not find signing key/);
    expect(decryptionResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID)
  });

  it('decryptMessage - output binary data should be transferred', async () => {
    const decryptionResult = await WorkerProxy.decryptMessage({
      armoredMessage: `-----BEGIN PGP MESSAGE-----

wy4ECQMIxybp91nMWQIAa8pGeuXzR6zIs+uE6bUywPM4GKG8sve4lJoxGbVS
/xN10jwBEsZQGe7OTWqxJ9NNtv6X6qFEkvABp4PD3xvi34lo2WUAaUN2wb0g
tBiO7HKQxoGj3FnUTJnI52Y0pIg=
=HJfc
-----END PGP MESSAGE-----`,
      passwords: 'password',
      format: 'binary'
    });
    expect(decryptionResult.data).to.deep.equal(stringToUtf8Array('hello world'));
    expect(decryptionResult.signatures).to.have.length(0);
    expect(decryptionResult.errors).to.not.exist;
    expect(decryptionResult.verified).to.equal(VERIFICATION_STATUS.NOT_SIGNED)
  });

  it('encryptMessage - output binary message and signatures should be transferred', async () => {
    const encryptionResult = await WorkerProxy.encryptMessage({
      textData: 'hello world',
      passwords: 'password',
      format: 'binary'
    });
    expect(encryptionResult.message.length > 0).to.be.true;

    const decryptionResult = await WorkerProxy.decryptMessage({
      binaryMessage: encryptionResult.message,
      passwords: 'password'
    });
    expect(decryptionResult.signatures).to.have.length(0);
    expect(decryptionResult.errors).to.not.exist;
    expect(decryptionResult.verified).to.equal(VERIFICATION_STATUS.NOT_SIGNED)
  });

  it('signMessage/verifyMessage - output binary signature and data should be transferred', async () => {
    const binarySignature = await WorkerProxy.signMessage({
      textData: 'hello world',
      format: 'binary',
      detached: true
    });
    expect(binarySignature.length > 0).to.be.true;

    const decryptionResult = await WorkerProxy.verifyMessage({
      textData: 'hello world',
      verificationKeys: [], // TODO replace once implemented
      binarySignature
    });
    expect(decryptionResult.data).to.equal('hello world');
    expect(decryptionResult.signatures).to.have.length(1);
    expect(decryptionResult.errors).to.not.exist;
    expect(decryptionResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_VALID);

    const invalidVerificationResult = await WorkerProxy.verifyMessage({
      textData: 'not signed data',
      verificationKeys: [], // TODO replace once implemented
      binarySignature,
      format: 'binary'
    });
    expect(invalidVerificationResult.data).to.deep.equal(stringToUtf8Array('not signed data'));
    expect(invalidVerificationResult.signatures).to.have.length(1);
    expect(invalidVerificationResult.errors).to.have.length(1);
    expect(invalidVerificationResult.verified).to.equal(VERIFICATION_STATUS.SIGNED_AND_INVALID)
  });
});

// });
