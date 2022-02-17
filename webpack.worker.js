const path = require('path');

module.exports = {
    mode: 'production',
    entry: {
        worker: './lib/worker/worker.ts'
    },

    output: {
        filename: '[name].js',
        path: path.resolve(__dirname, 'dist'),
        chunkFilename: 'worker.chunk.[name].js',
        clean: true
    },
    optimization: {
        chunkIds: 'named' // keep intelligible chunk names to identify which dep libraries they are from
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
