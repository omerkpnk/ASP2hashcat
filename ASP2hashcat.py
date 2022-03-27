import base64
import sys
import os
import argparse
import time
from pyfiglet import Figlet

#####################################################################################################
#                                ASP.Net Core Hash Identity Cracker                                 #
#                                                                                                   #
#   Version 2:                                                                                      #
#   PBKDF2 with HMAC-SHA1, 128-bit salt, 256-bit subkey, 1000 iterations.                           #
#   Format: { 0x00, salt, subkey }                                                                  #
#                                                                                                   #
#   Version 3:                                                                                      #
#   PBKDF2 with HMAC-SHA256, 128-bit salt, 256-bit subkey, 10000 iterations.                        #
#   Format: { 0x01, prf (UInt32), iter count (UInt32), salt length (UInt32), salt, subkey }         #
#                                                                                                   #
#   Twitter: @omer_kepenek                                                                          #
#####################################################################################################

f = Figlet(font='standard')
print("\033[5;36;49m")
print(f.renderText("ASP2hashcat"))
print("\033[0m")
parser = argparse.ArgumentParser(
    description="ASP.Net Core Identity Hash Cracker")

parser.add_argument('-i', '--input', type=str, metavar='',
                    required=True, help='Hash File')
parser.add_argument('-o', '--output', type=str, metavar='',
                    required=True, help='Ouput File')
parser.add_argument('-c', '--crack', action='store_true',
                    help='Crack hashes via hashcat (Requires hashcat!)')
parser.add_argument('-v', '--verbose', action='store_true',
                    help='Verbose mode')
parser.add_argument('-w', '--wordlist', type=str,
                    metavar='', help='Wordlist File')

args = parser.parse_args()


filename = args.input
hashfile = open(filename, "r")
readhashes = hashfile.readlines()
for hash in readhashes:
    b64_decoded = base64.b64decode(hash)
    hex_version = b64_decoded.hex()

    def versionCheck():
        global version
        if hex_version[:2] == "01":  # First byte determines the version
            version = "3"
            return "\033[1;33;49m[*] Version v3 detected! \033[0m"
        elif hex_version[:2] == "00":
            version = "2"
            return "\033[1;33;49m[*] Version v2 detected!\033[0m"

    def prfCheck():
        global prf
        if version == "3":
            if hex_version[2:10] == "00000001":
                prf = "sha256"
                # HashPasswordV3 uses HMACSHA256 by default
                return "[*] Pbkdf2Prf --> HMACSHA256"
        else:
            prf = "sha1"
            # HashPasswordV2 uses HMACSHA1 by defeault
            return "[*] Pbkdf2Prf --> HMACSHA1"

    def iterationCheck():
        global iteration
        if version == "3":
            iteration = "0x" + hex_version[10:18]
            iteration = int(iteration, 16)
            # It calculates the iteration count // HashPasswordV3 uses 10000 iteration by default
            return f"[*] Iteration -->  {iteration}"
        elif version == "2":
            iteration = 1000
            # HashPasswordV2 uses 1000 iteration by default
            return f"[*] Iteration -->  {iteration}"

    def saltLength():
        global salt_length
        if version == "3":
            salt_length = hex_version[18:26]
            salt_length = int(salt_length, 16)
            return f"[*] Salt Length -->  {salt_length}"
        return

    def verboseMode():
        print(versionCheck())
        print(prfCheck())
        print(iterationCheck())
        if version == "3":
            print(saltLength())
        print(hashcatFormat())
        print("------------------------------------------------------------------------------------------------------")
    def quiteMode():
        versionCheck()
        prfCheck()
        iterationCheck()
        saltLength()
        hashcatFormat()

    def hashcatFormat():
        if version == "3":
            salt_len = 26 + (salt_length*2)
            salt = bytearray.fromhex(hex_version[26:salt_len])
            encode_salt = base64.b64encode(salt)
            encode_salt = encode_salt.decode('ascii')
            subkey = bytearray.fromhex(hex_version[salt_len:])
            encoded_subkey = base64.b64encode(subkey)
            encoded_subkey = encoded_subkey.decode('ascii')

            # Final Hashcat Format
            hashcatFormat = f"[+] Hashcat Format: {prf}:{iteration}:{encode_salt}:{encoded_subkey}"

            if args.output:
                outputfile = args.output
                hashes = open(args.output, "a")
                hashes.write(
                    f"{prf}:{iteration}:{encode_salt}:{encoded_subkey}\n")
                return hashcatFormat
        elif version == "2":
            salt = bytearray.fromhex(hex_version[2:34])
            encode_salt = base64.b64encode(salt)
            encode_salt = encode_salt.decode('ascii')
            subkey = bytearray.fromhex(hex_version[34:])
            encoded_subkey = base64.b64encode(subkey)
            encoded_subkey = encoded_subkey.decode('ascii')

            # Final Hashcat Format
            hashcatFormat = f"[+] Hashcat Format: {prf}:{iteration}:{encode_salt}:{encoded_subkey}"
            if args.output:
                outputfile = args.output
                hashes = open(outputfile, "a")
                hashes.write(
                    f"{prf}:{iteration}:{encode_salt}:{encoded_subkey}\n")
                return hashcatFormat
    if args.verbose:
        verboseMode()
    else:
        quiteMode()

# Save to output file specified
print(f"\033[0;32;49m[+] Saved: {os.getcwd()}/{args.output}\033[0m")


def cracker():
    if version == "2":
        # Launch hashcat for HashPasswordV2
        hashcat_command = f"hashcat -m 12000 -a 0 -o results.txt {args.output} {args.wordlist}"
        os.system(hashcat_command)
    elif version == "3":
        # Launch hashcat for HashPasswordV3
        hashcat_command = f"hashcat -m 10900 -a 0 -o results.txt {args.output} {args.wordlist}"
        os.system(hashcat_command)


if args.crack:
    print("\033[1;35;49m[*] Hashcat Launching...\033[0m")
    time.sleep(2)
    cracker()
