const path = require('path');

module.exports = {
    mode: 'production',
    entry: {
        worker: './lib/worker/worker.js'
    },

    output: {
        filename: '[name].js',
        path: path.resolve(__dirname, 'dist'),
        clean: true
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
            options: {
                onlyCompileBundledFiles: true
            }
        }]
    }
};
