// Karma configuration
// Generated on Mon Dec 06 2021 17:59:38 GMT+0100 (Central European Standard Time)

module.exports = function(config) {
    config.set({
        // base path that will be used to resolve all patterns (eg. files, exclude)
        basePath: '',

        // frameworks to use
        // available frameworks: https://www.npmjs.com/search?q=keywords:karma-adapter
        frameworks: ['mocha', 'webpack'], // need karma-typescrit?

        plugins: ['karma-mocha', 'karma-chrome-launcher', 'karma-webpack', 'karma-spec-reporter'],

        // list of files / patterns to load in the browser
        files: [{ pattern: 'test/**/test.ts', watched: false }],

        // list of files / patterns to exclude
        exclude: [],

        // preprocess matching files before serving them to the browser
        // available preprocessors: https://www.npmjs.com/search?q=keywords:karma-preprocessor
        preprocessors: {
            // 'test/**/*.ts': 'karma-typescript'
            'test/**/test.ts': 'webpack'
        },

        webpack: {
            resolve: {
                fallback: {
                    stream: false,
                    buffer: false
                },
                extensions: ['', '.js', '.ts']
            },
            module: {
                rules: [{ test: /\.ts?$/, loader: 'ts-loader' }]
            }
        },

        // test results reporter to use
        // possible values: 'dots', 'progress'
        // available reporters: https://www.npmjs.com/search?q=keywords:karma-reporter
        reporters: ['spec'], // 'karma-typescript'],

        // web server port
        port: 9876,

        // enable / disable colors in the output (reporters and logs)
        colors: true,

        // level of logging
        // possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
        logLevel: config.LOG_INFO,

        // enable / disable watching file and executing tests whenever any file changes
        autoWatch: false,

        // start these browsers
        // available browser launchers: https://www.npmjs.com/search?q=keywords:karma-launcher
        browsers: ['ChromeHeadless'],

        // Continuous Integration mode
        // if true, Karma captures browsers, runs the tests and exits
        singleRun: false,

        // Concurrency level
        // how many browser instances should be started simultaneously
        concurrency: Infinity
    });
};
