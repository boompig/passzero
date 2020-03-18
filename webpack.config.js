const path = require('path');
const mode = (process.env.NODE_ENV === 'dev' ? 'development' : 'production');

module.exports = {
    mode: mode,
    entry: {
        'entries': './typescript/entries-bundle/index.tsx',
		'new-entry': './typescript/new-entry-bundle/index.tsx',
        'links': './typescript/links-bundle/index.tsx',
		'new-link': './typescript/new-link-bundle/index.tsx',
		'docs': './typescript/docs-bundle/index.tsx',
		'new-doc': './typescript/new-doc-bundle/index.tsx',
		'view-doc': './typescript/view-doc-bundle/index.tsx',
    },
    output: {
        filename: '[name].bundle.js',
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
                    path.resolve(__dirname, 'typescript/new-entry-bundle'),
                    path.resolve(__dirname, 'typescript/links-bundle'),
                    path.resolve(__dirname, 'typescript/new-link-bundle'),
                    path.resolve(__dirname, 'typescript/docs-bundle'),
                    path.resolve(__dirname, 'typescript/new-doc-bundle'),
                    path.resolve(__dirname, 'typescript/view-doc-bundle'),
                    path.resolve(__dirname, 'typescript/common'),
                ],
                exclude: [
                    path.resolve(__dirname, 'typescript/standalone'),
                    path.resolve(__dirname, 'static')
                ]
            },

            {
                test: /\.css$/,
                use: ["style-loader", "css-loader"],
            },

            // All output '.js' files will have any sourcemaps re-processed by 'source-map-loader'.
            { enforce: 'pre', test: /\.js$/, loader: 'source-map-loader' }
        ]
    }
};
