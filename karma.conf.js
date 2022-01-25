module.exports = function(config) {
    config.set({
        // base path that will be used to resolve all patterns (eg. files, exclude)
        basePath: '',

        // frameworks to use
        // available frameworks: https://www.npmjs.com/search?q=keywords:karma-adapter
        frameworks: ['mocha', 'webpack'],

        plugins: ['karma-mocha', 'karma-chrome-launcher', 'karma-webpack', 'karma-mocha-reporter'],

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

        // start these browsers
        // available browser launchers: https://www.npmjs.com/search?q=keywords:karma-launcher
        browsers: ['ChromeHeadless'],

        // Continuous Integration mode
        // if true, Karma captures browsers, runs the tests and exits
        singleRun: true,

        // Concurrency level
        // how many browser instances should be started simultaneously
        concurrency: Infinity,

        client: {
            mocha: {
              // timeout for mocha tests, default is 2 seconds. Some streaming tests can take longer.
              timeout : 12000
            }
          }
    });
};
