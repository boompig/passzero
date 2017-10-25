/* globals __dirname,  */
/* eslint-env node */

const CommonsChunkPlugin = require("webpack/lib/optimize/CommonsChunkPlugin");

module.exports = {
	context: __dirname + "/static/js/modules/",
	entry: {
		"view_docs": "./docs.jsx",
		"new_doc": "./new_doc.jsx"
	},

	output: {
		filename: "[name].chunk.js",
		path: __dirname + "/static/js/dist"
	},

	module: {
		loaders: [
			{ test: /\.js$/, loader: "babel-loader", exclude: /node_modules/ },
			{ test: /\.jsx$/, loader: "babel-loader", exclude: /node_modules/ },
		]
	},

	plugins: [
		new CommonsChunkPlugin("commons")
	]
};
