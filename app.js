// @ts-check
const pack = require('./package.json');
const fs = require('fs');
const path = require('path');
const { 
    Logger,
    C_HEX,
    PROGRAM,
    DIR_NAME,
    exit,
    ask,
    getPathInfo,
    ensurePathExists,
    readDirectoryFiles,
} = require('./src/common.js');
const {
    makeFileHash,
    read_text,
    recheckNames,
    xor_KTPD_file,
    extractFiles,
    _consoleLoadingBar
} = require('./src/functions.js')

// Set commands to program for
PROGRAM
  .name('KTPD_Unpacker')
  .description(`${C_HEX.blue}KTPD file list creator and unpacker${C_HEX.reset}`)
  .version(pack.version)

  .option(`-x, --extract <string>`, 'Extracts all files from the input KTPD file. Will make a table file is one isn\'t already created.')

  .option(`-h, --hash <string>`,    `Input a single file path string to see if it matches any hashes. Will add any matching file paths to local table.json files.`)

  .option(`-t, --text <string>`,    `Batch version of --hash. Input a text file and it will hash each line for a file match. Will also check names in any table files.`)
  
  .option('-r, --recheck',          `Rechecks all tables with all hashed file names.`)

PROGRAM.addHelpText("after",`
${C_HEX.red}WARNING:${C_HEX.reset} False positive hashes as possible, so do use sparingly!`)
PROGRAM.parse(process.argv);

/**
 * Command line arguments.
 */
const ARGV = PROGRAM.opts();

const input_set = new Set([
    /^-x/,  /^--extract/,
    /^-h/,  /^--hash/,
    /^-t/,  /^--text/,
    /^-r/,  /^--recheck/,
]);

/**
 * Filters out strings that match any regular expression in the provided set.
 *
 * @param {string[]} strings - An array of strings to be filtered.
 * @param {Set<RegExp>} regexSet - A set of regular expressions to test against the strings.
 * @returns {string[]} - An array of strings that do not match any of the regular expressions.
 */
function filterByRegex(strings, regexSet) {
    return strings.filter(str => ![...regexSet].some(regex => regex.test(str) ));
};
  
const _INPUT_FILE = filterByRegex(process.argv.slice(2), input_set)[0];

Logger.info(`Commands:`);
Logger.info(ARGV);
if(_INPUT_FILE != undefined){
    Logger.info(`File: ${C_HEX.yellow}${_INPUT_FILE}${C_HEX.reset}`);
};

// Starts app
(async function () {
    if(_INPUT_FILE){
         const {
            file_name, // with .ext
            name:input_base_name,
            ext:input_ext,
            dirname:input_root,
            full_path:input_full_path
        } = await getPathInfo(_INPUT_FILE);
        if(ARGV.text || input_ext == ".txt"){
            const TXT_INPUT = _INPUT_FILE || ARGV.text && ARGV.text.replace(/^=/,"");
            try {
                if(fs.existsSync(TXT_INPUT)){
                    const path_to_file_names = path.join(DIR_NAME, 'file_names.json');
                    var file_names;
                    if(!fs.existsSync(path_to_file_names)){
                        Logger.warn("No file name file, creating one.");
                        fs.writeFileSync(path_to_file_names,"{}");
                        file_names = {};
                    } else {
                        file_names = JSON.parse(fs.readFileSync(path_to_file_names).toString());
                    }
                    await read_text(TXT_INPUT, file_names, path_to_file_names);
                    await exit();
                } else {
                    Logger.error("File does not exist!");
                    Logger.error(TXT_INPUT);
                    await exit();
                }
            } catch (error) {
                Logger.error("Issue reading txt file.");
                Logger.error(error);
                await exit();
            }
            await exit();
        } else 
        if(ARGV.extract || input_ext != ".txt"){
            const input_file = _INPUT_FILE || ARGV.extract && ARGV.extract.replace(/^=/,"").trim();
            // check for file_names.json
            const path_to_file_names = path.join(DIR_NAME, 'file_names.json');
            var file_names;
            if(!fs.existsSync(path_to_file_names)){
                Logger.warn("No file name file, creating one.");
                fs.writeFileSync(path_to_file_names,"{}");
                file_names = {};
            } else {
                file_names = JSON.parse(fs.readFileSync(path_to_file_names).toString());
            }
            try {
                if(fs.existsSync(input_file)){
                    const path_to_file_names = path.join(DIR_NAME, 'file_names.json');
                    var file_names;
                    if(!fs.existsSync(path_to_file_names)){
                        Logger.warn("No file name file, creating one.");
                        fs.writeFileSync(path_to_file_names,"{}");
                        file_names = {};
                    } else {
                        file_names = JSON.parse(fs.readFileSync(path_to_file_names).toString());
                    }
                    Logger.info("Creating decrypted files.");
                    const base_file = fs.readFileSync(input_file);
                    const file_parse = await xor_KTPD_file(base_file,file_names);
                    const decrypt_path = path.join(input_root,input_base_name + "_decrypted.bin");
                    fs.writeFileSync(decrypt_path,file_parse.data);
                    Logger.info("Finished decrypting files.");

                    Logger.info("Writng table data.");
                    const tables_path = path.join(DIR_NAME, 'tables', input_base_name+".json");
                    ensurePathExists(tables_path);
                    if(!fs.existsSync(tables_path)){
                        fs.writeFileSync(tables_path, JSON.stringify(file_parse.table_parse, null, 4) );
                    } else {
                        Logger.warn(`Found table data for ${file_name} in table folder, skipping overwrite.`);
                    }
                    file_parse.tables_data.forEach((el,i)=>{
                        const table_path = path.join(input_root, input_base_name+`_table_${i+1}.bin`);
                        ensurePathExists(table_path);
                        fs.writeFileSync(table_path, el);
                    });
                    
                    Logger.info("Extracting compressed files...");
                    await extractFiles(file_parse.data, file_parse.table_parse, file_names, input_root, input_base_name);
                    Logger.info("Extraction complete!");
                    await exit();
                } else {
                    Logger.error("Input file does not exist!");
                    Logger.error(input_file);
                    await exit();
                }
            } catch (error) {
                Logger.error("Issue reading input file.");
                Logger.error(error);
                await exit();
            }
        }
        await exit();
    } else
    if(ARGV.hash){
        const hash_str = ARGV.hash.replace(/^=/,"");
        // check for file_names.json
        const path_to_file_names = path.join(DIR_NAME, 'file_names.json');
        var file_names;
        if(!fs.existsSync(path_to_file_names)){
            Logger.warn("No file name file, creating one.");
            fs.writeFileSync(path_to_file_names,"{}");
            file_names = {};
        } else {
            file_names = JSON.parse(fs.readFileSync(path_to_file_names).toString());
        }
        // create hash
        const new_hash = makeFileHash(hash_str);
        file_names[new_hash] = hash_str;
        Logger.info(`Checking for ${C_HEX.yellow}${new_hash}${C_HEX.reset} as ${C_HEX.yellow}${hash_str}${C_HEX.reset}`);

        // get any tables files
        const path_to_tables = path.join(DIR_NAME, 'tables');
        ensurePathExists(path_to_tables);

        // check if any tables have the file.
        const tables_paths = readDirectoryFiles(path_to_tables,".json");
        var matches_found = 0;
        for (let i = 0; i < tables_paths.length; i++) {
            var file_matches = 0;
            const el = tables_paths[i];
            const table_data = JSON.parse(fs.readFileSync(el).toString());
            table_data.forEach(element => {
                if( element.FILE_HASH == new_hash ){
                    if(element.FILE_NAME != undefined){
                        Logger.warn(`${C_HEX.yellow}${new_hash}${C_HEX.reset} already logged as: ${C_HEX.yellow}${element.FILE_NAME}${C_HEX.reset} in ${el}`);
                    } else {
                        element.FILE_NAME = hash_str;
                        Logger.info(`${C_HEX.green}Found${C_HEX.reset}: ${C_HEX.yellow}${hash_str}${C_HEX.reset} in ${el}`);
                        file_matches++;
                        matches_found++;
                    }
                }
            });
            if(file_matches > 0){
                Logger.info(`${C_HEX.green}Found ${file_matches} matches!${C_HEX.reset} in ${el}`);
            }
            // save file
            fs.writeFileSync(el,JSON.stringify(table_data, null, 4));
        }
        if(matches_found > 0){
            Logger.info(`${C_HEX.green}Found ${matches_found} total matches!${C_HEX.reset}`);
        }
        // save json data
        fs.writeFileSync(path_to_file_names,JSON.stringify(file_names,null,4));
        await exit();
    } else 
    if(ARGV.recheck){
        // check for file_names.json
        Logger.info(`Running recheck on file names`);
        const path_to_file_names = path.join(DIR_NAME, 'file_names.json');
        var file_names;
        if(!fs.existsSync(path_to_file_names)){
            Logger.warn("No file name file, creating one.");
            fs.writeFileSync(path_to_file_names,"{}");
            file_names = {};
        } else {
            file_names = JSON.parse(fs.readFileSync(path_to_file_names).toString());
        }
        // get any tables files
        const path_to_tables = path.join(DIR_NAME, 'tables');
        ensurePathExists(path_to_tables);

        // check if any tables have the file.
        const tables_paths = readDirectoryFiles(path_to_tables,".json");
        var matches_found = 0;
        for (let i = 0; i < tables_paths.length; i++) {
            var file_matches = 0;
            const el = tables_paths[i];
            Logger.info(`Checking ${el}`);
            const table_data = JSON.parse(fs.readFileSync(el).toString());
            const found = await recheckNames(table_data, file_names);
            file_matches += found;
            matches_found += found;
            if(file_matches > 0){
                Logger.info(`${C_HEX.green}Found ${file_matches} matches!${C_HEX.reset} in ${el}`);
            }
            // save file
            fs.writeFileSync(el,JSON.stringify(table_data, null, 4));
        }
        if(matches_found > 0){
            Logger.info(`${C_HEX.green}Found ${matches_found} total matches!${C_HEX.reset}`);
        }
        // save json data
        fs.writeFileSync(path_to_file_names,JSON.stringify(file_names,null,4));
        Logger.info(`Recheck complete!`);
        await exit();
    } else {
        await exit();
    }
    
})();