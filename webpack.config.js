const path = require('path');

module.exports = {
    mode: 'development',
    entry: './typescript/entries-bundle/index.tsx',
    output: {
        filename: 'entries.bundle.js',
        path: __dirname + '/static/js/dist'
    },

    // Enable sourcemaps for debugging webpack's output.
    devtool: 'source-map',

    resolve: {
        // Add '.ts' and '.tsx' as resolvable extensions.
        extensions: ['.ts', '.tsx', '.js']
    },

    module: {
        rules: [
            // All files with a '.ts' or '.tsx' extension will be handled by 'awesome-typescript-loader'.
            {
                test: /\.tsx?$/,
                loader: 'awesome-typescript-loader',
                include: [
                    path.resolve(__dirname, 'typescript/entries-bundle'),
                    path.resolve(__dirname, 'typescript/common'),
                ],
                exclude: [
                    path.resolve(__dirname, 'typescript/standalone'),
                    path.resolve(__dirname, '_OLD'),
                    path.resolve(__dirname, 'static')
                ]
            },

            // All output '.js' files will have any sourcemaps re-processed by 'source-map-loader'.
            { enforce: 'pre', test: /\.js$/, loader: 'source-map-loader' }
        ]
    },
    externals: {
        'pzAPI': '../common/passzero_api'
    }
};
