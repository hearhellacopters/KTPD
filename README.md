# KTPD file Decrypt and Extract

An all in one tool for file name hashing, files decompiling and KTPD files (Koei Tecmo Pack Files). Tested on Three Kingdoms Heroes. File list included is missing files but gets a bulk of the job done.

## What is this?

Some Koei Tecmo games outside of Three Kingdoms Heroes may have KTPD files, this tool was create for file extraction and retaining the file paths for easier file management. The game uses hashed file name so you'll need to know the names for the files to be writen with the correct path. There is an command to testing file names that will check all tables for any of the KTPD files you have run it on.

## How does it work?

The included exe is Windows x64 but can be built for other systems. It is a simple command line tool that you can use by dropping files on it or running [commands](#commands).

## Commands

Here are all the commands the exe accepts.

**Note:** You can also find all these commands in the --help command.

### extract

> -x for short.

Extracts all files in the selected KTPD file.

**Note:** Any unknown file names will be given a .dat extension with their hash name.

Can also be run by droping the KTPD file on the exe.

```cmd
KTPD_Unpacker-x64.exe --extract="C:/RTKHEROES/fonts.bin"
```

### hash

> -h for short.

Basic hash command to check if the file name is in a file list.

**Note:** False positive may be possible!

```cmd
KTPD_Unpacker-x64.exe --hash="res/spine_u_1500_elite_01_00_00_01.skel"
```

### text

> -t for short.

This is the batch command for --hash. Enter a text file path and it will hash each line.

```cmd
KTPD_Unpacker-x64.exe --text="C:/RTKHEROES/file_names.txt"
```

### recheck

> -r for short.

Rechecks all tables for any hashes currently in the file_names.json file.

```cmd
KTPD_Unpacker-x64.exe --recheck"
```