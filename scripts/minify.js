"use strict";

const fs = require("fs");
const path = require("path");
const childProcess = require("child_process");
const CleanCSS = require("clean-css");

function compressFiles(srcDir, distDir) {
    fs.readdir(srcDir, (err, items) => {
        if(err) {
            console.error(err);
            throw err;
        }
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
}

function compressCssFiles(srcDir, distDir) {
    fs.readdir(srcDir, (err, items) => {
        if(err) {
            console.error(err);
            throw err;
        }
        items.filter((item) => {
            let itemPath = path.join(srcDir, item);
            return item.endsWith(".css") && fs.statSync(itemPath).isFile();
        }).map((item) => {
            let srcPath = path.join(srcDir, item);
            let distFname = item.replace(/\.css$/, ".min.css");
            let distPath = path.join(distDir, distFname);
            let contents = fs.readFileSync(srcPath);
            console.log(`[clean-css] ${srcPath} -> ${distPath}`);
            let output = new CleanCSS().minify(contents);
            fs.writeFileSync(distPath, output.styles);
        });
    });
}

compressFiles("static/js/src", "static/js/dist");
compressCssFiles("static/css/src", "static/css/dist");
