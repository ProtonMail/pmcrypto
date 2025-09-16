/* eslint-disable @typescript-eslint/no-require-imports */
/* global require, process, module */
const { firefox, chromium, webkit } = require('playwright');

process.env.CHROME_BIN = chromium.executablePath();
process.env.FIREFOX_BIN = firefox.executablePath();
process.env.WEBKIT_HEADLESS_BIN = webkit.executablePath();

module.exports = function(config) {
    config.set({
        // base path that will be used to resolve all patterns (eg. files, exclude)
        basePath: '',

        // frameworks to use
        // available frameworks: https://www.npmjs.com/search?q=keywords:karma-adapter
        frameworks: ['mocha', 'webpack'],

        plugins: [
            'karma-mocha',
            'karma-webpack',
            'karma-mocha-reporter',
            'karma-chrome-launcher',
            'karma-firefox-launcher',
            'karma-webkit-launcher'
        ],

        // list of files / patterns to load in the browser
        files: [{ pattern: 'test/**/*.*', watched: false }],

        // list of files / patterns to exclude
        exclude: [],

        // preprocess matching files before serving them to the browser
        // available preprocessors: https://www.npmjs.com/search?q=keywords:karma-preprocessor
        preprocessors: {
            'test/**/*.*': 'webpack'
        },

        webpack: {
            optimization: {
                nodeEnv: 'production' // silence OpenPGP.js debug errors, triggered by some tests
            },
            resolve: {
                fallback: {
                    stream: false,
                    buffer: false
                },
                extensions: ['', '.js', '.ts']
            },
            module: {
                rules: [{
                    test: /\.ts?$/,
                    loader: 'ts-loader',
                    options: { compilerOptions: { noEmit: false } }
                }]
            }
        },

        // available reporters: https://www.npmjs.com/search?q=keywords:karma-reporter
        reporters: ['mocha'],

        // web server port
        port: 9876,

        // enable / disable colors in the output (reporters and logs)
        colors: true,

        // level of logging
        // possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
        logLevel: config.LOG_INFO,

        // enable / disable watching file and executing tests whenever any file changes
        autoWatch: false,

        customLaunchers: {
            ChromeHeadlessCI: {
                base: 'ChromeHeadless',
                flags: ['--no-sandbox']
            }
        },
        browsers: ['ChromeHeadlessCI', 'FirefoxHeadless', 'WebkitHeadless'],

        // Continuous Integration mode
        // if true, Karma captures browsers, runs the tests and exits
        singleRun: true,

        // Concurrency level
        // how many browser instances should be started simultaneously
        concurrency: Infinity,

        client: {
            mocha: {
                // timeout for mocha tests, default is 2 seconds. Some streaming tests can take longer.
                timeout: 30000
            }
        },

        browserDisconnectTimeout: 30000,
        browserNoActivityTimeout: 45000
    });
};
