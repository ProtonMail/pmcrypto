import { use as chaiUse } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';

import { init } from '../lib';

chaiUse(chaiAsPromised);
before(init);