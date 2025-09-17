// @ts-check
import eslint from '@eslint/js';
import { defineConfig } from 'eslint/config';
import tseslint from 'typescript-eslint';
import globals from 'globals';
// @ts-expect-error
import pluginChaiFriendly from 'eslint-plugin-chai-friendly';
import pluginImport from 'eslint-plugin-import';
// @ts-expect-error
import pluginEnforceUint8ArrayArrayBuffer from '@protontech/eslint-plugin-enforce-uint8array-arraybuffer';
import pluginStylistic from '@stylistic/eslint-plugin';

export default defineConfig(
    eslint.configs.recommended,
    tseslint.configs.recommendedTypeChecked,
    {
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'module',
            parserOptions: {
                projectService: true,
                tsconfigRootDir: import.meta.dirname
            },
            globals: {
                ...globals.browser,
                ...globals.mocha
            }
        },
        settings: {
            'import/resolver': {
                typescript: { 'alwaysTryTypes': true }
            }
        },
        plugins: {
            'chai-friendly': pluginChaiFriendly,
            'import': pluginImport,
            '@protontech/enforce-uint8array-arraybuffer': pluginEnforceUint8ArrayArrayBuffer,
            '@stylistic': pluginStylistic
        },
        rules: {
            'prefer-spread': 'off',
            'no-restricted-syntax': 'off',
            'arrow-parens': ['error', 'always'],
            'indent': 'off',
            'comma-dangle': ['error', 'never'],
            'consistent-return': 'off',
            'object-curly-newline': 'off',
            'prefer-template': 'off',
            'no-plusplus': 'off',
            'no-continue': 'off',
            'no-bitwise': 'off',
            'no-await-in-loop': 'off',
            'no-sequences': 'warn',
            'no-param-reassign': 'warn',
            'no-return-assign': 'warn',
            'no-else-return': ['error', { allowElseIf: true }],
            'no-shadow': 'off',
            'no-unused-expressions': 'off',
            'no-undef': 'error',
            'no-cond-assign': 'error',
            'one-var-declaration-per-line': 'error',
            'new-cap': ['error', {
                newIsCap: true,
                newIsCapExceptions: [],
                capIsNew: false
            }],
            'class-methods-use-this': 'error',
            'chai-friendly/no-unused-expressions': [ 'error', { allowShortCircuit: true } ],
            'arrow-body-style': 'off',
            'space-before-function-paren': 'off',
            'operator-linebreak': 'off',
            'implicit-arrow-linebreak': 'off',
            'no-underscore-dangle': 'off',
            'import/no-unresolved': ['error', {
                ignore: ['.data']
            }],
            'import/prefer-default-export': 'off',
            'import/no-extraneous-dependencies': 'off',
            'import/no-unassigned-import': 'error',
            'import/named': 'error',
            'import/extensions': 'error',
            'max-len': ['error', {
                ignoreComments: true,
                code: 120,
                ignoreStrings: true,
                ignoreTemplateLiterals: true,
                ignoreRegExpLiterals: true
            }],
            'no-restricted-imports': ['error', {
                name: 'openpgp',
                message: 'Please import from \'lib/openpgp\' instead.'
            }],
            'no-multiple-empty-lines': ['error'],
            'no-trailing-spaces': ['error'],
            'eol-last': ['error'],
            'camelcase': ['error', { allow: ['openpgp_*'] }],
            'padded-blocks': 'off',
            '@protontech/enforce-uint8array-arraybuffer/enforce-uint8array-arraybuffer': 'error',

            '@typescript-eslint/naming-convention': ['error', {
                selector: 'typeLike',
                format: ['PascalCase', 'UPPER_CASE']
            }],
            '@typescript-eslint/ban-ts-comment': 'off',
            '@typescript-eslint/consistent-type-imports': 'error',
            '@typescript-eslint/consistent-type-exports': 'error',
            '@typescript-eslint/no-empty-object-type': ['error', { allowInterfaces: 'with-single-extends' }],
            '@typescript-eslint/no-unused-expressions': 'off',
            '@typescript-eslint/no-unused-vars': 'error',
            '@typescript-eslint/no-unsafe-call': 'off', // function call to fn with `any` type
            '@typescript-eslint/no-unsafe-member-access': 'off',
            '@typescript-eslint/no-unsafe-argument': 'off',
            '@typescript-eslint/no-unsafe-assignment': 'off',
            '@stylistic/indent': ['error', 4],
            '@stylistic/quotes': ['error', 'single'],
            '@stylistic/no-multiple-empty-lines': ['error', { max: 1 }],
            '@typescript-eslint/comma-dangle': 'off'
        }
    });
