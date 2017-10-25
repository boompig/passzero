/* globals __dirname,  */
/* eslint-env node */

const path = require("path");

module.exports = {
	context: __dirname + "/static/js/src/",
	entry: {
		"view_docs": "./docs.jsx",
		"new_doc": "./new_doc.jsx"
	},

	output: {
		filename: "[name].bundle.js",
		path: __dirname + "/static/js/dist"
	},

	module: {
		loaders: [
			{ test: /\.js$/, loader: "babel-loader", exclude: /node_modules/ },
			{ test: /\.jsx$/, loader: "babel-loader", exclude: /node_modules/ },
		]
	}
};
