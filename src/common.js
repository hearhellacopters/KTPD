// @ts-check
const { Command } = require('commander');
const { hexdump } = require('bireader');
const fs = require('fs');
const path = require('path');
const keypress = require('keypress');
const { 
    confirm, 
    checkbox, 
    select,
    Separator 
} = require('@inquirer/prompts');
const inputs = require('@inquirer/prompts').input;

/**
 * How the app parses arguments passed to it at the command line level.
 * 
 * @class
 */
const PROGRAM = new Command();

/**
 * For console log colors
 * 
 * @readonly
 * @enum {string}
 */
const C_HEX = {
    white:        '\x1b[37m',
    black:        '\x1b[30m',
    red:          '\x1b[31m', //error
    green:        '\x1b[32m', 
    yellow:       '\x1b[33m', //info
    blue:         '\x1b[36m', //debug
    magenta:      '\x1b[35m', //warn

    red_back:     '\x1b[41m',
    green_back:   '\x1b[42m',
    yellow_back:  '\x1b[43m',
    blue_back:    '\x1b[46m',
    magenta_back: '\x1b[45m',
    white_back:   '\x1b[47m',

    red_yellow:   '\x1b[31;43m',
    reset:        '\x1b[0m'  // ending
};

/**
 * Base path where server is running.
 * 
 * @returns {string} directory name
 */
function _get_dir_name(){
    // @ts-ignore
    if(process.pkg){
        return path.dirname(process.execPath);
    } else {
        return process.cwd();
    }
};

/**
 * Base path where server is running.
 * 
 * Used in finding files to load.
 */
const DIR_NAME = _get_dir_name();

/**
 * Static Class for creating and conveting Dates in JavaScript format and others.
 * 
 * @class 
 */
class JSDate {
    /**
     * Shortcut for ``New Date().GetTime()``
     * 
     * @static
     * @returns {number} Returns the stored time value in milliseconds since midnight, January 1, 1970 UTC.
     */
    static get ct(){
        return new Date().getTime();
    }

    /**
     * Get time as string. Used in Logger. Example: ``'2024.03.03-01.00.00AM'``
     * 
     * @static
     * @returns {string} `year.month.day-hours.minutes.seconds amOrPm`
     */
    static currentTime(){
        const now = new Date();

        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        let hours = now.getHours();
        const minutes = String(now.getMinutes()).padStart(2, '0');
        const seconds = String(now.getSeconds()).padStart(2, '0');
        const amOrPm = hours >= 12 ? 'PM' : 'AM';
    
        // Convert hours to 12-hour format
        hours = hours % 12 || 12;
    
        return `${year}.${month}.${day}-${hours}.${minutes}.${seconds}${amOrPm}`;
    }

    /**
     * For formated date strings: ``'Thu, Feb 8, 2024, 07:09:20 AM'``
     * 
     * Mostly for transmissions header
     * 
     * @static
     * @param {Date|string|number|undefined} date - ``new Date()`` by default
     * @returns {string} Example ``'Thu, Feb 8, 2024, 07:09:20 AM'``
     */
    static humanReadable(date = undefined){
        if(date != undefined){
            if( typeof date == "string" ||
                typeof date == "number"
            ){
                date = new Date(date);
            } else if(!(date instanceof Date)){
                Logger.error("Date must be an instanceof new Date()");
                exit();
            }
        } else {
            date = new Date();
        };

        return new Intl.DateTimeFormat('en-US', {
            day: "numeric",
            month: "short", 
            year: "numeric", 
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            timeZone: 'UTC',
            weekday: "short",
        }).format(date);
    }

    /**
     * Formats date for master data. Example: ``'2017-04-14 15:00:00'``
     * 
     * @static
     * @param {Date|string|number|undefined} date - ``new Date()`` by default
     * @returns {string} Example: ``'2017-04-14 15:00:00'``
     */
    static masterFormat(date){
        if(date != undefined){
            if( typeof date == "string" ||
                typeof date == "number"
            ){
                date = new Date(date);
            } else if(!(date instanceof Date)){
                Logger.error("Date must be an instanceof new Date()");
                exit();
            }
        } else {
            date = new Date();
        };
        const year = date.getFullYear();
        const month = (date.getMonth() + 1).toString().padStart(2, '0');
        const day = date.getDate().toString().padStart(2, '0');
        const hours = date.getHours().toString().padStart(2, '0');
        const minutes = date.getMinutes().toString().padStart(2, '0');
        const seconds = date.getSeconds().toString().padStart(2, '0');
        return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
    }

    /**
     * Get a time offset of supplied years from now. Great for editing existing time data or setting something to forever. 
     * 
     * Returns master data format string. Example: ``'2017-04-14 15:00:00'``
     * 
     * @static
     * @param {Date|string|number|undefined} date - Date as number, Date instance or string. Defaults to Current Time.
     * @param {number} years - offset of years from now
     * @returns {number} time as a number
     */
    static getYearsFromNumber(date, years){
        if(years == undefined){
            Logger.error("Years offset must be set");
            exit();
        }
        if(date != undefined){
            if( typeof date == "string" ||
                typeof date == "number"
            ){
                date = new Date(date);
            } else if(!(date instanceof Date)){
                Logger.error("Date must be an instanceof new Date()");
                exit();
            }
        } else {
            date = new Date();
        };
        const date2 = new Date(date.getTime() + years * (365.25 * 24 * 60 * 60 * 1000));
        return date2.getTime();
    }

    /**
     * Get a time offset of supplied years from now. Great for editing existing time data or setting something to forever. 
     * 
     * Returns master data format string. Example: ``'2017-04-14 15:00:00'``
     * 
     * @static
     * @param {Date|string|number|undefined} date - Date as number, Date instance or string. Defaults to Current Time.
     * @param {number} years - offset of years from now
     * @returns {string} master data format string. Example: ``'2017-04-14 15:00:00'``
     */
    static getYearsFromString(date, years){
        if(years == undefined){
            Logger.error("Years offset must be set");
            exit();
        }
        if(date != undefined){
            if( typeof date == "string" ||
                typeof date == "number"
            ){
                date = new Date(date);
            } else if(!(date instanceof Date)){
                Logger.error("Date must be an instanceof new Date()");
                exit();
            }
        } else {
            date = new Date();
        };
        const date2 = new Date(date.getTime() + years * (365.25 * 24 * 60 * 60 * 1000));
        const year = date2.getFullYear();
        const month = String(date2.getMonth() + 1).padStart(2, '0');
        const day = String(date2.getDate()).padStart(2, '0');
        return `${year}-${month}-${day} 00:00:00`;
    }

    /**
     * Quickly get a time offset of 20 years from date. Great for editing existing time data or setting something to forever. 
     * 
     * Returns master data format string. Example: ``'2017-04-14 15:00:00'``
     * 
     * @static
     * @param {Date|string|number|undefined} date - Date as number, Date instance or string. Defaults to Current Time.
     * @returns {string} master data format string. Example: ``'2017-04-14 15:00:00'``
     */
    static get20YearsFromString(date){
        return this.getYearsFromString(date, 20);
    }

    /**
     * Quickly get a time offset of 20 years from now. Great for editing existing time data or setting something to forever. 
     * 
     * Returns master data format string. Example: ``'2017-04-14 15:00:00'``
     * 
     * @static
     * @returns {string} master data format string. Example: ``'2017-04-14 15:00:00'``
     */
    static get20YearsFromNowString(){
        return this.getYearsFromString(new Date(), 20);
    }

    /**
     * Quickly get a time offset of 20 years from now. Great for editing existing time data or setting something to forever. 
     * 
     * @static
     * @returns {number} time as a number
     */
    static get20YearsFromNowNumber(){
        return this.getYearsFromNumber(new Date(), 20);
    }

    /**
     * Quickly get a time offset of 20 years from date. Great for editing existing time data or setting something to forever. 
     * 
     * @static
     * @param {Date|string|number|undefined} date - Date as number, Date instance or string. Defaults to Current Time.
     * @returns {number} time as a number
     */
    static get20YearsFromNumber(date){
        return this.getYearsFromNumber(date, 20);
    }

    /**
     * Get a time offset of supplied years from now. Great for editing existing time data or setting something to forever. 
     * 
     * @static
     * @param {number} years - offset of years from now
     * @returns {number} time as a number
     */
    static getYearsFromNowNumber(years){
        return this.getYearsFromNumber(new Date(), years);
    }

    /**
     * Get a time offset of supplied years from now. Great for editing existing time data or setting something to forever. 
     * 
     * Returns master data format string. Example: ``'2017-04-14 15:00:00'``
     * 
     * @static
     * @param {number} years - offset of years from now
     * @returns {string} master data format string. Example: ``'2017-04-14 15:00:00'``
     */
    static getYearsFromNowString(years){
        return this.getYearsFromString(new Date(), years);
    }
};

/**
 * Ask a yes / no question.
 * 
 * Example:
 * 
 * ```
 * ask("Continue?").then(answer=>{
 *      if(answer){
 *      //do something
 *      }
 * }).catch(err=>{
 *      //error catch
 * })
 * ```
 * 
 * @async
 * @param {string} question - Question to ask.
 * @returns {Promise<boolean>} Promise
 */
async function ask(question){
    const questions = {
            type: 'confirm',
            message: question,
            defalt: false
    };

    return new Promise((resolve, reject) => {
        try {
            confirm(questions).then(answer => {
                resolve(answer);
            });
        } catch (error) {
            reject();
        }
    });
};

/**
 * An input of a single select list (single selection).
 * 
 * Example:
 * 
 * ```
 * const questions = [
 *    {
 *        value: 'Extra Cheese'
 *    },
 *    {
 *        value: 'Pepperoni'
 *    }
 * ]
 * choose("What would you like on your pizza?", questions).then(answers=>{
 *      if(answers){
 *      //do something
 *      }
 * }).catch(err=>{
 *      //error catch
 * })
 * ```
 * 
 * @async
 * @param {string} title - Title of the selection.
 * @param {{value: string, disabled?: boolean | string, description?: string }[]} questions - Array of answers to select.
 * @returns {Promise<string>} Promise
 */
async function choose(title, questions) {

    const new_array_of_questions = questions.map((question) => {
        if(question.value == undefined){
            return new Separator();
        } else {
            return question;
        }
    });

    const question = {
        message: title,
        choices: new_array_of_questions,
        required: true,
    };

    return new Promise((resolve, reject) => {
        try {
            select(question).then(answer => {
                resolve(answer);
            });
        } catch (error) {
            reject();
        }
    });
};

/**
 * An input of multi select checkboxes (multi select).
 * 
 * Example:
 * 
 * ```
 * const questions = [
 *    {
 *        value: 'Extra Cheese'
 *    },
 *    {
 *        value: 'Pepperoni'
 *    }
 * ]
 * select("What would you like on your pizza?", questions).then(answers=>{
 *      if(answers){
 *      //do something
 *      }
 * }).catch(err=>{
 *      //error catch
 * })
 * ```
 * 
 * @async
 * @param {string} title - Title of the selection.
 * @param {{value: string, disabled?: boolean | string, description?: string }[]} questions - Array of answers to select.
 * @returns {Promise<string[]>} Promise
 */
async function selects(title, questions) {

    const new_array_of_questions = questions.map((question) => {
        if(question.value == undefined){
            return new Separator();
        } else {
            return question;
        }
    });

    const question = {
        message: title + "\n",
        choices: new_array_of_questions,
        required: true,
    };

    return new Promise((resolve, reject) => {
        try {
            checkbox(question).then(answer => {
                resolve(answer);
            });
        } catch (error) {
            reject();
        }
    });
};

/**
 * Ask for input based on question. Input can't be blank.
 * 
 * Example:
 * 
 * ```
 * input("What is your name?").then(answer=>{
 *      if(answer){
 *      //do something
 *      }
 * }).catch(err=>{
 *      //error catch
 * })
 * ```
 * 
 * @async
 * @param {string} question - Question to ask.
 * @returns {Promise<string>} Promise
 */
async function input(question){
    const questions = {
            message: question,
            required: true,
    };

    return new Promise((resolve, reject) => {
        try {
            inputs(questions).then(answer => {
                resolve(answer);
            });
        } catch (error) {
            reject();
        }
    });
};

/**
 * A press any key to exit function.
 * 
 * @async
 */
async function exit() {
    // Enable keypress events on stdin
    keypress(process.stdin);

    console.log('Press any key to exit...');

    /**
     * Create a promise to handle key press
     * @returns {Promise<any>} Promise
     */
    function getKeyPress() {
        return new Promise(resolve => {
            var pressed = true;
            process.stdin.on('keypress', (_, key) => {
                if (pressed && key) {
                    pressed = false;
                    console.log("Exiting...");
                    setTimeout(() => {
                        process.exit(0);
                    }, 2000);
                }
            });

            // Set raw mode to capture all key events
            process.stdin.setRawMode(true);
            process.stdin.resume();
        });
    }

    // Wait for key press
    await getKeyPress();

    // Clean up keypress events
    process.stdin.setRawMode(false);
    process.stdin.pause();
};

/**
 * Logger base class. Not to be used outside of ``Logger``
 * 
 * @class
 */
class _CustomLog {
    constructor() {
        //if(!fs.existsSync(path.join(DIR_NAME, `/logs`))){
        //    fs.mkdirSync(path.join(DIR_NAME, `/logs`), { recursive: true });
        //}
        //this.loc = path.join(DIR_NAME, `/logs/${JSDate.currentTime()}.log`);
    }
    /**
     * Log function.
     * @param {string} level - file and location
     * @param {string|number|object|boolean|undefined} text - message
     */
    log(level, text) {
        var message = text;
        if(typeof message == "number" ||
           typeof message == "boolean"){
            message = `${text}`;
        } else
        if( typeof message == "object" &&
            !(message instanceof Error)
        ){
            message = JSON.stringify(text, null, 4);
        } else
        if(message == undefined){
            message = "undefined";
        }
        //const writeStream = fs.createWriteStream(this.loc, { flags: 'a' });
        //const regexRemove = /\x1b\[[0-9;]*[mG]/g;
        // Write the text to the file
        //writeStream.write((level + " " + message).replace(regexRemove, '') + '\n');

        // Listen for the 'finish' event to know when the write operation is complete
        //writeStream.on('finish', () => {
        //    // Close the write stream
        //    writeStream.end();
        //});

        console.log(level, message); // Call console.log
    }
};

const _cl = new _CustomLog();

/**
 * Class Logger. 
 * 
 * ```javascript 
 * // Start as new if you want to use a timer.
 * const LG = new Logger("timerLabel");
 * // End timer with:
 * LG.end(); // does NOT repect log level
 * ```
 * 
 * Use ``Logger.debug()`` - Debug log. Highest level log. Adds timestamp, filename and line.
 * 
 * Use ``Logger.warn()`` - Warn log. Logs and writes if at warn or above. Adds timestamp.
 * 
 * Use ``Logger.error()``- Error log. Logs and writes if at error or above. Adds timestamp, filename and line.
 * 
 * Use``Logger.info()`` - Info log. Always logs and writes this. No extra info.
 * 
 * Use``Logger.log()`` - For dev use only. A console.log() with file and line info. Does NOT write to log.
 * 
 * Only creates log if matching log level is met.
 */
class Logger {
    #label = "";
    #startTime = 0;
    /**
     * Only need a new constructor when using a timer with ``.end()``.
     * @param {string} label - Label for timer in logs.
     */
    constructor(label){
        if(typeof label == "string"){
            this.#label = label;
            this.#startTime = JSDate.ct;
        }
    }
    /**
     * A ``console.log()`` with file and location.
     * 
     * Does not respect log level or write to log file.
     * 
     * Do NOT use on builds!
     * 
     * Only for temporary dev programming.
     * 
     * @static
     * @param {any} message - Message to log.
     */
    static log(...message){

        for (var key = 0; key < message.length; key++) {
            const text = message[key];
            if( typeof text == "number" ||
                typeof text == "boolean"
            ){
                message[key] = `${text}`;
            } else
            if(text instanceof Error){
                message[key] = text.stack;
            } else
            if( typeof text == "object"){
                message[key] = JSON.stringify(text, null, 4);
            } else
            if(text == undefined){
                message[key] = `undefined`;
            }
        }

        const err = new Error();

        // Extract the stack trace information
        const stackTrace = err.stack ? err.stack.split('\n')[2].trim() : "";

        // Updated regular expression to capture file and line information
        const match = stackTrace.match(/\s*at .+ \((.*):(\d+):(\d+)\)/) ||
        stackTrace.match(/\s*at (.*):(\d+):(\d+)/);
    
        // Extract the file name, line number, and column number
        const fileName = match ? path.basename(match[1]) : null;
        const lineNumber = match ? match[2] : null;
        console.log(`${fileName}:${lineNumber} -`, message.join(" "));
    }

    /**
     * Info log. Always logs and writes this.
     * 
     * No extra info.
     * 
     * @static
     * @param {number|boolean|object|string} message - Message to log.
     */
    static info(...message){

        for (var key = 0; key < message.length; key++) {
            const text = message[key];
            if( typeof text == "number" ||
                typeof text == "boolean"
            ){
                message[key] = `${text}`;
            } else
            if(text instanceof Error){
                message[key] = text.stack;
            } else
            if( typeof text == "object"){
                message[key] = JSON.stringify(text, null, 4);
            } else
            if(text == undefined){
                message[key] = `undefined`;
            }
        }

        _cl.log(`${C_HEX.blue}[info]${C_HEX.reset}`, message.join(" "));
    };

    /**
     * Error log. Logs and writes if at error or above.
     * 
     * Adds timestamp, filename and line.
     * 
     * @static
     * @param {number|boolean|object|string} message - Message to log
     */
    static error(...message){

        for (var key = 0; key < message.length; key++) {
            const text = message[key];
            if( typeof text == "number" ||
                typeof text == "boolean"
            ){
                message[key] = `${text}`;
            } else
            if(text instanceof Error){
                message[key] = text.stack;
            } else
            if( typeof text == "object"){
                message[key] = JSON.stringify(text, null, 4);
            } else
            if(text == undefined){
                message[key] = `undefined`;
            }
        }

        const err = new Error();

        // Extract the stack trace information
        const stackTrace = err.stack ? err.stack.split('\n')[2].trim() : "";

        // Updated regular expression to capture file and line information
        const match = stackTrace.match(/\s*at .+ \((.*)\)/) ||
        stackTrace.match(/\s*at (.*)/);
    
        // Extract the file name, line number, and column number
        const fileName = match ? path.basename(match[1]) : null;
        
        _cl.log(`${C_HEX.red}[error]${C_HEX.reset} ${fileName ? fileName : ""} -`, message.join(" "));
    };

    /**
     * Warn log. Logs and writes if at warn or above.
     * 
     * Adds timestamp.
     * 
     * @static
     * @param {number|boolean|object|string} message - Message to log
     */
    static warn(...message){

        for (var key = 0; key < message.length; key++) {
            const text = message[key];
            if( typeof text == "number" ||
                typeof text == "boolean"
            ){
                message[key] = `${text}`;
            } else
            if(text instanceof Error){
                message[key] = text.stack;
            } else
            if( typeof text == "object"){
                message[key] = JSON.stringify(text, null, 4);
            } else
            if(text == undefined){
                message[key] = `undefined`;
            }
        }
        
        _cl.log(`${C_HEX.magenta}[warn]${C_HEX.reset}`, message.join(" "));
    };

    /**
     * Debug log. Highest level log.
     * 
     * Adds timestamp, filename and line.
     * 
     * @static
     * @param {number|boolean|object|string} message - Message to log
     */
    static debug(...message){

        for (var key = 0; key < message.length; key++) {
            const text = message[key];
            if( typeof text == "number" ||
                typeof text == "boolean"
            ){
                message[key] = `${text}`;
            } else
            if(text instanceof Error){
                message[key] = text.stack;
            } else
            if( typeof text == "object"){
                message[key] = JSON.stringify(text, null, 4);
            } else
            if(text == undefined){
                message[key] = `undefined`;
            }
        }

        const err = new Error();
    
        // Extract the stack trace information
        const stackTrace = err.stack ? err.stack.split('\n')[2].trim() : "";
    
        // Updated regular expression to capture file and line information
        const match = stackTrace.match(/\s*at .+ \((.*)\)/) ||
        stackTrace.match(/\s*at (.*)/);
    
        // Extract the file name, line number, and column number
        const fileName = match ? path.basename(match[1]) : null;
    
        _cl.log(`${C_HEX.blue}[debug]${C_HEX.reset} ${fileName ? fileName : ""} -`, message.join(" "));
    }

    /**
     * Logs ends timer if class is started with ``new`` and with a label.
     */
    end(){
        if(this.#label == ""){
            Logger.error("Timer can not end with being started with new Logger('timer label')");
        }
        const err = new Error();

        // Extract the stack trace information
        const stackTrace = err.stack ? err.stack.split('\n')[2].trim() : "";

        // Updated regular expression to capture file and line information
        const match = stackTrace.match(/\s*at .+ \((.*)\)/) ||
        stackTrace.match(/\s*at (.*)/);
    
        // Extract the file name, line number, and column number
        const fileName = match ? path.basename(match[1]) : null;

        const dif = JSDate.ct - this.#startTime;
        const milliseconds = dif % 1000;
        const totalSeconds = Math.floor(dif / 1000);
        const seconds = totalSeconds % 60;
        const totalMinutes = Math.floor(totalSeconds / 60);
        const minutes = totalMinutes % 60;
        const hours = Math.floor(totalMinutes / 60);
        if(hours){
            const msg = `${hours}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}.${milliseconds} hours`;
            _cl.log(`${C_HEX.yellow}[timer ${this.#label}]${C_HEX.reset}: ${fileName ? fileName : ""} - `, msg);
        }
        if(minutes){
            const msg = `${minutes}:${String(seconds).padStart(2, '0')}.${milliseconds} mins`;
            _cl.log(`${C_HEX.yellow}[timer ${this.#label}]${C_HEX.reset}: ${fileName ? fileName : ""} - `, msg);
        }
        if(seconds){
            const msg = `${seconds}.${milliseconds} sec`;
            _cl.log(`${C_HEX.yellow}[timer ${this.#label}]${C_HEX.reset}: ${fileName ? fileName : ""} - `, msg);
        }
        _cl.log(`${C_HEX.yellow}[timer ${this.#label}]${C_HEX.reset}: ${fileName ? fileName : ""} - `, `${milliseconds} msec`);
    }
};

/**
 * Resolves the provided file path to an absolute path.
 * If the input is a relative path, it will resolve it based on the current working directory.
 * If the input is already an absolute path, it returns it as is.
 * 
 * @param {string} filePath - The file path (absolute or relative).
 * @returns {string} - The resolved absolute file path.
 */
function resolveFilePath(filePath) {
    // Check if the filePath is already an absolute path
    if (path.isAbsolute(filePath)) {
        return filePath;
    }
    
    // If the path is relative, resolve it against the current working directory
    const cwd = process.cwd();
    const resolvedPath = path.resolve(cwd, filePath);
    
    return resolvedPath;
}

/**
 * returns path file info
 * @async
 * @param {string} file_src 
 * @returns {Promise<{file_name:string,name:string,ext:string,dirname:string,full_path:string}>}
 */
async function getPathInfo(file_src){
    const path_name2 = resolveFilePath(file_src);
    const ext = path.extname(path_name2).toLocaleLowerCase(); // w/ dot
    const name = path.parse(path_name2).name;                 // without ext
    const file_name = path.basename(path_name2);              // with .ext
    const file_path = path.dirname(path_name2);
    return {
        file_name,
        name,
        ext,
        dirname: file_path,
        full_path: path_name2
    };
}

/**
 * Ensures that a given path exists as a file or directory.
 * 
 * Will write data if passed.
 * 
 * @param {string} targetPath - The path to check or create.
 * @param {any} fileData - Data for the file
 */
function ensurePathExists(targetPath, fileData = undefined) {
    const isFile = !!path.extname(targetPath);
    if (fs.existsSync(targetPath)) {
        const stats = fs.statSync(targetPath);
        // Path already exists as file, but we want folder
        if (!isFile && stats.isFile()) {
            fs.mkdirSync(targetPath, { recursive: true });
            return;
        }
    }

    // Path does not exist, create it
    if (!isFile) {
        // targetPath is a folder so create it
        fs.mkdirSync(targetPath, { recursive: true });
    } else if (isFile) {
        // targetPath is a file so make sure folder path is created
        const dir = path.dirname(targetPath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        if(fileData){
            // writes file data if supplied
            fs.writeFileSync(targetPath, fileData);
        }
    }
}

/**
 * Returns a list of all files inside the given folder path.
 * 
 * @param {string} folderPath - The path of the folder to list files from.
 * @param {string| undefined} only_type - Only return subfolders with this extension.
 * @returns {string[]} - An array of file names inside the given folder.
 */
function readDirectoryFiles(folderPath, only_type = undefined) {
    try {
        const file = fs.readdirSync(folderPath);
        const list = [];
        file.forEach(item => {
            const itemPath = path.join(folderPath, item);
            const Ext = path.extname(itemPath);
            if(only_type){
                if(Ext == only_type && fs.statSync(itemPath).isFile()){
                    list.push(itemPath);
                }
            } else 
            if(fs.statSync(itemPath).isFile()){
                list.push(itemPath);
            }
        });
        return list;
    } catch (error) {
        return [];
    }
};

module.exports = {
    JSDate,
    Logger,

    C_HEX,

    PROGRAM,
    DIR_NAME,
   
    hexdump,
    exit,
    ask,
    input,
    selects,
    choose,

    getPathInfo,
    ensurePathExists,
    readDirectoryFiles
};