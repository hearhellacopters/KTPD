// @ts-check
const {
    brotliDecompressSync,
} = require('zlib');
const { 
    Logger,
    C_HEX,
    DIR_NAME,
    ensurePathExists,
    readDirectoryFiles,
    exit
} = require('./common.js');
const {exts} = require('./codes.js');
const fs = require('fs');
const path = require('path');

/**
 * Loading bar function.
 * 
 * @param {number} totalSteps - total pos
 * @param {number} currentStep - current pos
 * @returns {number}
 */
function _consoleLoadingBar(totalSteps, currentStep) {
    var barLength = 40;
    // Calculate the percentage completed
    const percentage = (currentStep / totalSteps) * 100;

    // Calculate the number of bars to display
    const bars = Math.floor((barLength * currentStep) / totalSteps);

    // Create the loading bar string
    const loadingBar = '[' + '='.repeat(bars) + '>'.repeat(bars < barLength ? 1 : 0) + ' '.repeat(barLength - bars) + ']';

    // Print the loading bar to the console
    process.stdout.clearLine(0); // Clear the previous line
    process.stdout.cursorTo(0); // Move the cursor to the beginning of the line
    process.stdout.write(`${C_HEX.green}${loadingBar}${C_HEX.reset} - ${percentage.toFixed(2)}% - ${currentStep} of ${totalSteps}`);
    return 1;
};

/**
 * Hashes file name
 * @param {string} name file name
 * @returns 
 */
function makeFileHash(name) {
    var hash_value = new Uint32Array([0x128FA6B3]);
    for (let i = 0; i < name.length; i++) {
        let cur = new Uint32Array([name.charCodeAt(i)]); // Get character code
        // Replace '\' with '/'
        if (cur[0] == 92) {
            cur[0] = 47;
        }
        // Convert lowercase letters to uppercase
        if (cur[0] >= 0x61 && cur[0] <= 0x7A) {
            cur[0] -= 32;
        }
        hash_value[0] = (0x1B3D * hash_value[0]) + cur[0];
    }
    return hash_value[0];
};

/**
 * Another hash function I found. No idea what for. Hashes color names like red and blue.
 * @param {string} name 
 * @returns 
 */
function makeColorHash(name) {
    var hash_value = 0n;
    for (let i = 0; i < name.length; i++) {
        let cur = name.charCodeAt(i); // Get character code
        // Replace '\' with '/'
        if (cur == 92) {
            cur = 47;
        }
        // Convert lowercase letters to uppercase
        if ((cur - 97) < 0x1A) {
            cur -= 32;
        }
        hash_value = (0x69B2F55n * hash_value) + BigInt(cur);
    }
    return Number(hash_value & 0xFFFFFFFFn);
};

/**
 * Basic read function
 * @param {Buffer} data 
 * @param {number} offset 
 * @returns {number}
 */
function readUint32(data, offset) {
    return ((data[offset + 3] << 24) |
        (data[offset + 2] << 16) |
        (data[offset + 1] << 8) |
        data[offset]) >>> 0;
};

/**
 * decrpyts a location and returns the first 4 bytes for type checking.
 * @param {Buffer} data Buffer data
 * @param {number} key Hex key
 * @param {number} off Offset
 * @param {number} amount amount of data to process
 * @returns {Promise<number>}
 */
async function decryptLoc(data, key, off, amount, add = 0x1F, shift = 0x0B) {
    var rotate = new Uint32Array([key]);
    for (let i = 0; i != amount; ++i) {
        var el = data[off + i];
        el ^= ((rotate[0] >> shift) & 0xff) ^ ((rotate[0] >> 24) & 0xff);
        data[off + i] = el;
        rotate[0] += add;
    }
    return readUint32(data, off);
}

/**
 * Decrypt a KTPD file
 * @param {Buffer} buffer - file to decrypt
 * @param {object} file_names - file names to check against
 * @returns {Promise<{ data: Buffer, table_parse:object, tables_data:Buffer[]}>}
 */
async function xor_KTPD_file(buffer, file_names) {
    var decrypt = true;
    if(readUint32(buffer,0) != 1146115147){ // KTPD
        Logger.error(`Not a KTPD file.`);
        await exit();
    }

    if(buffer[5] != 5){
        Logger.warn(`File is not flaged as compressed or encrypted. But will continue...`);
    }

    if(buffer[7] == 0){
        Logger.warn(`File doesn't not appear to be encrypted, will parse file without decrypting it.`);
        decrypt = false;
    }

    // decrypt 32 byte header
    if(decrypt){
        Logger.info(`Decrypting header.`);
        var rotate = new Uint32Array([0x117]);
        var add = 0x19F26D04;
        var shift = 0x0B;
        var off = 6, amount = 26;
        // header 32 bytes
        for (let i = 0; i != amount; ++i )
        {
            var el = buffer[off+i];
            el ^= rotate[0] >> shift;
            buffer[off+i] = el;
            rotate[0] += add;
        }
    }

    const table1_decomp_size = readUint32(buffer, 8) * 24; // dont need window for process

    const data_start = readUint32(buffer, 12);

    const table2 = readUint32(buffer, 20);

    const table2_decomp_size = readUint32(buffer, 24) * 24; // dont need window for process

    var table_size;
    if (table2) {
        table_size = table2 - 0x20;
    } else {
        table_size = data_start - 0x20;
    }

    // Second header w/ CBPT data
    if(decrypt){
        Logger.info(`Decrypting table.`);
        Logger.info(table_size);
        await decryptLoc(buffer, 0x96A17B35 + 9, 0x20, table_size);
    }
    const is_CBPT_table = readUint32(buffer, 0x20);
    if(is_CBPT_table != 1413632067){ // CPBT
        Logger.error(`Table is not flaged as compressed.`);
        Logger.info(`File magics: 0x${is_CBPT_table.toString(16)}`);
        return {data:buffer, table_parse:[],tables_data:[]};
    }

    const tables_data = [];
    Logger.info(`Decompress table.`);
    tables_data.push(brotliDecompressSync(buffer.subarray(0x30,0x30+table_size)));

    if (table2) {
        // decrypt table 2
        const table2_size = data_start - table2;
        if(decrypt){
            Logger.info(`Decrypting table 2.`);
            await decryptLoc(buffer,0x5B0F1643 + 9,table2,table2_size);
        }
        const is_CBPT_table2 = readUint32(buffer,table2);
        if(is_CBPT_table2 != 1413632067){ // CPBT
            Logger.error(`Table2 is not flaged as compressed.`);
            Logger.warn(`Returning just the first table.`);
            return {data:buffer, table_parse:[], tables_data: tables_data};
        }
        Logger.info(`Decompress table 2.`);
        tables_data.push(brotliDecompressSync(buffer.subarray(table2+0x10,table2+table2_size)));
    }

    // parse table1
    const table_parse = [];
    Logger.info(`Parsing table.`);
    const NUM_OF_FILES = tables_data[0].length / 24;
    for (let i = 0; i < NUM_OF_FILES; i++) {
        _consoleLoadingBar(NUM_OF_FILES, i + 1);
        const el = tables_data[0];
        const entry = {};
        entry.FILE_HASH = readUint32(el, i * 24 + 0);
        if(file_names[entry.FILE_HASH]){
            entry.FILE_NAME = file_names[entry.FILE_HASH];
        }
        entry.data2     = readUint32(el, i * 24 + 4); // always 0 likely because hash was meant for 64 bits
        entry.OFFSET    = readUint32(el, i * 24 + 8) + data_start;
        entry.SIZE      = readUint32(el, i * 24 + 12);
        entry.FLAG      = readUint32(el, i * 24 + 16); // pretty much always 0x90000005 for compressed and xored
        entry.HASH2     = readUint32(el, i * 24 + 20); // maybe post decomp crc?
        table_parse.push(entry);
    }
    process.stdout.write('\n');
    table_parse.sort((el, el2) => el.OFFSET - el2.SIZE);

    // decrypt rest of the file
    if(decrypt){
        Logger.info(`Decrypting file contents.`);
        for (let i = 0; i < table_parse.length; i++) {
            const el = table_parse[i];
            const comp_type = await decryptLoc(buffer, el.FILE_HASH + 9, el.OFFSET, el.SIZE);
            if (comp_type != 1413632067) {
                Logger.error(`File @ 0x${el.OFFSET.toString(16)} w/ unknown compression type: `, "0x" + comp_type.toString(16));
            }
        }
    }
    return { data: buffer, table_parse, tables_data };
};

/**
 * Extracts files from buffer
 * @param {Buffer} base_file 
 * @param {object} table_parse 
 * @param {object} file_names 
 * @param {string} input_root
 * @param {string} input_base_name
 * @returns {Promise<boolean>}
 */
async function extractFiles(base_file, table_parse, file_names, input_root, input_base_name){
    const NUM_OF_FILES = table_parse.length;
    for (let i = 0; i < NUM_OF_FILES; i++) {
        const el = table_parse[i];
        _consoleLoadingBar(NUM_OF_FILES, i + 1);
        // check file names and add if needed
        if( el.FILE_NAME == undefined && file_names[el.FILE_HASH]){
            el.FILE_NAME = file_names[el.FILE_HASH];
        }
        var ext = ".dat", ex_data;
        const comp_type = readUint32(base_file, el.OFFSET); 
        if (comp_type == 1413632067) { // CPBT
            ex_data = brotliDecompressSync(base_file.subarray(el.OFFSET + 0x10, el.OFFSET + el.SIZE));
            const magic_test = readUint32(ex_data,0);
            if(exts[magic_test]){ //adds ext to unknown files
                ext = exts[magic_test];
            }
        } else {
            Logger.error(`File @ 0x${el.OFFSET.toString(16)} w/ unknown compression type: `, "0x" + comp_type.toString(16));     
            ex_data = base_file.subarray(el.OFFSET,el.OFFSET+el.SIZE);
        }
        const file_ex_path = path.join(input_root, input_base_name, el.FILE_NAME ? el.FILE_NAME : el.FILE_HASH.toString(16) + ext);
        ensurePathExists(file_ex_path);
        fs.writeFileSync(file_ex_path, ex_data);
    }
    process.stdout.write('\n');
    return true;
}

/**
 * Checks all known hashes on table
 * @param {object[]} table_parse 
 * @param {object} file_names 
 * @returns 
 */
async function recheckNames(table_parse, file_names){
    var found = 0;
    for (let i = 0; i < table_parse.length; i++) {
        const el = table_parse[i];
        if( el.FILE_NAME == undefined && file_names[el.FILE_HASH]){
            el.FILE_NAME = file_names[el.FILE_HASH];
            Logger.info(`${C_HEX.green}Found${C_HEX.reset}: ${C_HEX.yellow}${file_names[el.FILE_HASH]}${C_HEX.reset}`);
            found++;
        }
    }
    return found;
}

/**
 * Reads a text file line by line, hashes each line, and checks if the hash
 * is associated with a filename in the provided file list. If no filename
 * is found, assigns the line as the filename.
 *
 * @param {string} TXT_FILE - The path to the text file to read.
 * @param {Object} file_names - An object mapping file hashes to their metadata, including filenames.
 * @param {string} path_to_file_names - Path to file names
 * @returns {Promise<any>} - Returns 1 if a new filename is assigned, 0 if the hash already has a filename, or does nothing if the hash is not found.
 */
async function read_text(TXT_FILE, file_names, path_to_file_names){
    const TEXT_DATA = fs.readFileSync(TXT_FILE, 'utf8').split('\n');
    const path_to_tables = path.join(DIR_NAME, 'tables');
    ensurePathExists(path_to_tables);
    const tables_paths = readDirectoryFiles(path_to_tables,".json");
    const hashes_to_check = [];
    for (let i = 0; i < TEXT_DATA.length; i++) {
        const str = TEXT_DATA[i].trim();
        const hash_num = makeFileHash(str);
        Logger.info(`${C_HEX.magenta}Path:${C_HEX.reset} ${C_HEX.yellow}${str}${C_HEX.reset}`);
        Logger.info(`Number:`, hash_num);
        hashes_to_check.push({
            file_name: str,
            hash_num: hash_num
        });
        file_names[hash_num] = str;
    }
    Logger.info(`Checking hashes in all tables...`);
    var matches_found = 0;
    for (let i = 0; i < tables_paths.length; i++) {
        var file_matches = 0;
        const el = tables_paths[i];
        const table_data = JSON.parse(fs.readFileSync(el).toString());
        hashes_to_check.forEach(el0 => {
            const search = table_data.find((el1)=>el1.FILE_HASH == el0.hash_num);
            if(search){
                if(search.FILE_NAME != undefined){
                    Logger.warn(`${C_HEX.yellow}${el0.hash_num}${C_HEX.reset} already logged as: ${C_HEX.yellow}${search.FILE_NAME}${C_HEX.reset} in ${el}`);
                } else {
                    search.FILE_NAME = el0.file_name;
                    Logger.info(`${C_HEX.green}Found${C_HEX.reset}: ${C_HEX.yellow}${el0.file_name}${C_HEX.reset} in ${el}`);
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
    return matches_found;
}

module.exports = {
    makeFileHash,
    makeColorHash,
    extractFiles,
    xor_KTPD_file,
    recheckNames,
    read_text,
    _consoleLoadingBar
}