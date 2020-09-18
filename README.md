# PlugX v1 string decryptor

## This is a simple script to decrypt the strings in the version of PlugX malware using a single-byte XOR encryption. 
## This script was created for demonstration purposes for the REcon 2018 talk "Malware Analysis and Automation using Binary Ninja" https://recon.cx/2018/montreal/schedule/events/130.html 

## Requirements:
A current license of Binary Ninja including scripting functionality is required. 
Python and the yara-python module (https://github.com/VirusTotal/yara-python) are also required for this script, as well as the yara file included in this repository. 
 
## Usage: plugx_decrypt_strings.py <file>

This script currently assumes all necessary files to be in the working directory of the script (TODO to take in a directory as input), and will output the modified DLL to the same directory.
The following hash is an example sample that can be used with this script (this file is malware, but can be provided upon request): 

$ md5 AShldRes.dll 
MD5 (AShldRes_org.dll) = 2fbb87311dbc96508b1c471d9abab041
$ shasum -a 256 AShldRes_org.dll 
6f3f9604eac2ea37cb3c8198e446cbbf24987c4a59350da265214b0009ff39c9  AShldRes_org.dll
