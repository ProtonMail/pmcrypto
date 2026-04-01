import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

const testFilesToInclude = ['test/**/*.spec.ts'];

export default defineConfig({
    test: {
        include: testFilesToInclude,
        setupFiles: ['./test/setup.ts'],
        testTimeout: 30000,
        typecheck: {
            // run tsc directly instead for now, since this breaks on e.g. `it.next()` in `streamFromChunks`
            enabled: false,
            include: testFilesToInclude // typechecking is run over these files only
        },
        browser: {
            provider: playwright(),
            enabled: true,
            headless: true,
            screenshotFailures: false,
            instances: [
                { browser: 'chromium' },
                { browser: 'firefox' },
                { browser: 'webkit' }
            ]
        }
    }
});
