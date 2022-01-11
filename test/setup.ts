import { use as chaiUse } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import * as openpgp from 'openpgp';

import { init } from '../lib/pmcrypto';

chaiUse(chaiAsPromised);

before(() => {
    init(openpgp);
});
