import { globSync, existsSync } from 'fs';
import { playwrightLauncher, playwright } from '@web/test-runner-playwright';
import { esbuildPlugin } from '@web/dev-server-esbuild';
import { rollupBundlePlugin } from '@web/dev-server-rollup';
import rollupCommonjs from '@rollup/plugin-commonjs';
import rollupNodeResolve from '@rollup/plugin-node-resolve';
import rollupTypescript from '@rollup/plugin-typescript';

const sharedPlaywrightCIOptions = {
    headless: true
};

export default {
    files: ['test/**/*.spec.ts'],
    plugins: [
      // bn.js exposes a UMD module that isn't handled properly by ebuild
      // (https://github.com/evanw/esbuild/issues/507#issuecomment-1221091273).
      // Rollup's commonjs plugin works fine as part of `rollupBundlePlugin`,
      // but not if called directly as a web-test-runner plugin (i.e. `fromRollup(...)`).
      // bn.js is only used in tests, so it may be dropped in the future, in which case the
      // `rollupBundlePlugin` step may be dropped (however, a reason to keep it is that it enforces
      // type-checks, unlike esbuild that only does type-stripping).
      rollupBundlePlugin({
        rollupConfig: {
          plugins: [
            rollupTypescript(),
            rollupCommonjs({
              include: /bn.js/
            }),
            rollupNodeResolve({ exportConditions: ['browser'], })
          ],
          input: globSync('test/**/*.ts'),
          output: { sourcemap: 'inline' }
        },
      }),
      esbuildPlugin({
        // `rollupBundlePlugin` already compiles TS files to JS,
        // but passes them over with the same extension.
        // The `ts` option would normally do type-stripping,
        // but in this case it's basically a no-op that simply
        // adds support for the `.ts` extension
        ts: true
      }),
    ],
    testFramework: {
        config: {
            timeout: '20000'
        }
    },
    protocol: 'http:',
    hostname: '127.0.0.1',
    testsStartTimeout: 45000,
    browserStartTimeout: 120000,
    testsFinishTimeout: 450000,
    concurrentBrowsers: 3,
    coverage: false,
    groups: [
        { name: 'local' }, // group meant to be used with either --browser or --manual options via CLI
        {
            name: 'headless:ci',
            browsers: [
                playwrightLauncher({
                    ...sharedPlaywrightCIOptions,
                    product: 'chromium'
                }),
                playwrightLauncher({
                    ...sharedPlaywrightCIOptions,
                    product: 'firefox'
                }),
                // try setting up webkit, but ignore if not available
                // (e.g. on ubuntu, where we don't want to test webkit as the WebCrypto X25519 implementation has issues)
                existsSync(playwright.webkit.executablePath()) && playwrightLauncher({
                    ...sharedPlaywrightCIOptions,
                    product: 'webkit'
                })
            ].filter(Boolean)
        }
    ]
};
