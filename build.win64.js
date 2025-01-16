/**
 * @file for creating an executable .exe file for windows.
 */

const exe = require("@hearhellacopters/exe");
const package = require('./package.json');

const build = exe({
  entry: "./app.js",
  out: "./KTPD_Unpacker-x64.exe",
  pkg: ["-C", "GZip"], // Specify extra pkg arguments
  version: package.version,
  target: "node20-win-x64",
  icon: "./app.ico", // Application icons must be same size prebuild target
  // executionLevel: "highestAvailable"
});

build.then(() => console.log("Windows x64 build completed!"));