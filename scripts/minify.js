"use strict";

const fs = require("fs");
const path = require("path");
const childProcess = require("child_process");

const srcDir = "static/js/src";
const distDir = "static/js/dist";

fs.readdir(srcDir, (err, items) => {
    items.filter((item) => {
        let itemPath = path.join(srcDir, item);
        return item.endsWith(".js") && fs.statSync(itemPath).isFile();
    }).map((fname) => {
        let srcPath = path.join(srcDir, fname);
        let distFname = fname.replace(/\.js$/, ".min.js");
        let distPath = path.join(distDir, distFname);
        let command = [
            "node_modules/uglify-js/bin/uglifyjs",
            srcPath,
            "-o",
            distPath
        ].join(" ");
        console.log(`[uglifyjs] ${srcPath} -> ${distPath}`);
        childProcess.execSync(command);
    });
});
