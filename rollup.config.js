import babel from 'rollup-plugin-babel';
import stripCode from 'rollup-plugin-strip-code';
import pkg from './package.json';


export default [
    {
        input: 'lib/index.js',
        output: {
            file: pkg.browser,
            format: 'iife'
        },
        name: 'pmcrypto',
        plugins: [
            stripCode({
                start_comment: 'START.NODE_ONLY',
                end_comment: 'END.NODE_ONLY'
            }),
            babel()
        ]
    },
    {
        input: 'lib/index.js',
        output: {
            file: pkg.main,
            format: 'cjs'
        },
        name: 'pmcrypto',
        plugins: [
            stripCode({
                start_comment: 'START.BROWSER_ONLY',
                end_comment: 'END.BROWSER_ONLY'
            }),
            babel()
        ]
    }
];
