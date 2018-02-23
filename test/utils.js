import test from 'ava';
import utils from '../lib/utils';

// Add btoa and atob to Node
global.btoa = (str) => Buffer.from(str).toString('base64');
global.atob = (b64) => Buffer.from(b64, 'base64').toString();
global.openpgp = require('openpgp');

const strBaseSimple1 = 'I do a test 123';
const strBaseSimple2 = 'àsçiî+éà'; // extended ascii
const strBaseComplex1 = 'a0éÐ ö°§🙂 (╯°□°）╯';
const strBaseComplex2 = 'こんにちは、世界!';

test('encode_utf8', (t) => {
    t.truthy(utils.encode_utf8('') === '');
    t.truthy(utils.encode_utf8(strBaseSimple1) === strBaseSimple1);
    t.truthy(utils.encode_utf8(strBaseComplex1) === 'a0Ã©Ã Ã¶Â°Â§ð (â¯Â°â¡Â°ï¼â¯');
});

test('decode_utf8', (t) => {
    t.truthy(utils.decode_utf8('') === '');
    t.truthy(utils.decode_utf8(strBaseSimple1) === strBaseSimple1);
    t.truthy(utils.decode_utf8('a0Ã©Ã Ã¶Â°Â§ð (â¯Â°â¡Â°ï¼â¯') === strBaseComplex1);
});

test('encode_base64', (t) => {
    t.truthy(utils.encode_base64('') === '');
    t.truthy(utils.encode_base64(strBaseSimple1) === 'SSBkbyBhIHRlc3QgMTIz');
    t.truthy(utils.encode_base64('🙂') === '8J+Zgg==');
    t.truthy(utils.encode_base64(strBaseComplex1) === 'YTDDqcOQIMO2wrDCp/CfmYIgKOKVr8Kw4pahwrDvvInila8=');
    t.truthy(utils.encode_base64(strBaseComplex2) === '44GT44KT44Gr44Gh44Gv44CB5LiW55WMIQ==');
});

test('decode_base64', (t) => {
    t.truthy(utils.decode_base64('') === '');
    t.truthy(utils.decode_base64('SSBkbyBhIHRlc3QgMTIz') === strBaseSimple1);
    t.truthy(utils.decode_base64('8J+Zgg==') === '🙂');
    t.truthy(utils.decode_base64('YTDDqcOQIMO2wrDCp/CfmYIgKOKVr8Kw4pahwrDvvInila8=') === strBaseComplex1);
    t.truthy(utils.decode_base64('44GT44KT44Gr44Gh44Gv44CB5LiW55WMIQ==') === strBaseComplex2);
});

test('binaryStringToArray', (t) => {
    t.deepEqual(utils.binaryStringToArray(''), Uint8Array.from([]));
});

test('arrayToBinaryString', (t) => {
    t.truthy(utils.arrayToBinaryString([]) === '');
});

test('binaryStringToArray & arrayToBinaryString', (t) => {
    // Should be a "bijection"

    const arrBS1 = utils.binaryStringToArray(strBaseSimple1);
    const arrBS2 = utils.binaryStringToArray(strBaseSimple2);
    t.truthy(strBaseSimple1 === utils.arrayToBinaryString(arrBS1));
    t.truthy(strBaseSimple2 === utils.arrayToBinaryString(arrBS2));

    // ⚠️ Unicode strings need to be encoded and decoded
    const arrBC1 = utils.binaryStringToArray(utils.encode_utf8(strBaseComplex1));
    const arrBC2 = utils.binaryStringToArray(utils.encode_utf8(strBaseComplex2));
    t.truthy(strBaseComplex1 === utils.decode_utf8(utils.arrayToBinaryString(arrBC1)));
    t.truthy(strBaseComplex2 === utils.decode_utf8(utils.arrayToBinaryString(arrBC2)));
});

// test('getHashedPassword', (t) => {
//     t.truthy(utils.getHashedPassword('') === 'z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==');
//     t.truthy(utils.getHashedPassword(strBaseSimple1) === 'Q9m7u+/OBHRM8Zc0dJhfg+YYCLl5oki4i8ww4gIh2Ibzb4F7o7l1xdMY/cl/lso06Jc+2ixo1aikR5zh1foDvw==');
//     t.truthy(utils.getHashedPassword(strBaseComplex2) === 'NroK5vidb7CDqH6b7/2nxN1zZMR/qPDKNuhkvo4X/aGsOCcNmW3xHpMe3rDkxVi55uiEE52BKwpwnGo02mapjw==');
// });

