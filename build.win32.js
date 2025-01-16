/**
 * @file for creating an executable .exe file for windows.
 */

const exe = require("@hearhellacopters/exe");
const package = require('./package.json');

const build32 = exe({
  entry: "./app.js",
  out: "./KTPD_Unpacker.exe",
  pkg: ["-C", "GZip"], // Specify extra pkg arguments
  version: package.version,
  target: "node20-win-x86",
  icon: "./app.ico", // Application icons must be same size prebuild target
  // executionLevel: "highestAvailable"
});

build32.then(() => console.log("Windows x32 build completed!"));