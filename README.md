# Introduction
ASP2hashcat is a tool that allows you to convert AspNet Core Identity Hash v2 and v3 to hashcat format and crack it via hashcat if you wish. It is written in Python.

## How does it work?
ASP2hashcat decodes the base64 identity hash to unencoded data bytes and then converts the byte-like object to the hexadecimal version. 

- Version 3 uses HMAC-SHA256 Prf, 128-bit salt, 256-bit subkey, and 10000 iterations by default.
- Version 2 uses HMAC-SHA1 Prf, 128-bit salt, 256-bit subkey, and 1000 iteration by default.

### Steps
First of all, it determines the version from the first byte of hexadecimal data.

If it's version 3:
1) It uses the next 4 bytes to determine the Prf used
2) Then the next 4 bytes are converted to integers to find the iteration count
3) Then the next 4 bytes are converted to integers to find the length of the salt
5) It takes the next 16 bytes as salt and encode to base64 in order to use in hashcat format
6) It takes the next 32 bytes as subkey and encode to base64 in order to use in hashcat format

If it's version 2: 
1) It takes the next 16 bytes as salt and encodes to base64 in order to use in hashcat format.
2) It takes the next 32 bytes as subkey and encode to base64 in order to use in hashcat format.

When the conversion phase is complete, it will write the result to the output file you specified. If the **--crack** option is used, it starts hashcat to crack all converted hashes and writes to **results.txt** file.

# Demonstration Video

## AspNet Core Identity Hash v2

[![asciicast](https://asciinema.org/a/X734lRxR362yY3c8plfSWXxjZ.svg)](https://asciinema.org/a/X734lRxR362yY3c8plfSWXxjZ)

## AspNet Core Identity Hash v3

[![asciicast](https://asciinema.org/a/AGhufk5hViy9Permp1r0kSFSp.svg)](https://asciinema.org/a/AGhufk5hViy9Permp1r0kSFSp)
