#!/usr/bin/python
# AUTHOR: @DeniCocaCola
# Hashes a file or string in MD5, SHA1, or SHA256

import hashlib
import os

usrType = ''
usrTxt = ''
usrFile = ''
hashType = ''
hasher = hashlib.md5()

##
print('Current working directory: ' + os.getcwd())
hashType = input("Type 'MD5'[1], 'SHA1'[2],  or 'SHA256'[3] for desired hash: ")
usrType = input("Do you want to import a file to hash? <Y/N>: ")


##FILE HASHING FUNCTIONS
def hashFile():
    if hashType in {'md5','MD5','Md5','mD5','1'}:
        hasher = hashlib.md5()
        try:
            usrFile = input("Enter path for file: ")
            with open(usrFile, 'rb') as afile:
                buf = afile.read()
                hasher.update(buf)  
                print(hasher.hexdigest())
        except FileNotFoundError:
            errorPath()
    elif hashType in {'sha1','SHA1','Sha1','2'}:
        hasher = hashlib.sha1()
        try:
            usrFile = input("Enter path for file: ")
            with open(usrFile, 'rb') as afile:
                buf = afile.read()
                hasher.update(buf)
                print(hasher.hexdigest())
        except FileNotFoundError:
            errorPath()
    elif hashType in {'sha256','SHA256','Sha256','3'}:
        hasher = hashlib.sha256()
        try:
            usrFile = input("Enter path for file: ")
            with open(usrFile, 'rb') as afile:
                buf = afile.read()
                hasher.update(buf)
                print(hasher.hexdigest())
        except FileNotFoundError:
            errorPath()

##ERROR RESPONSE
def errorPath():
    progRetry = input("File not found, or invalid path. Try again? <Y/N>:")
    if progRetry in {"Y","y"}:
        hashFile()
    else:
        print("Closing.")
        exit


##USER OPTIONS FUNCTIONS
if usrType == "Y" or usrType == "y":
    hashFile()

elif usrType == "N" or usrType == "n":
    usrTxt = input("Enter text to hash: ")
    if hashType in {'md5','MD5','Md5','1'}:
        hasher = hashlib.md5(str(usrTxt).encode('utf-8'))
        print(hasher.hexdigest())
##
    elif hashType in {'sha1','SHA1','Sha1','2'}:
        hasher = hashlib.sha1(str(usrTxt).encode('utf-8'))
        print(hasher.hexdigest())
##
    elif hashType in{'sha256','SHA256','Sha256','3'}:
        hasher = hashlib.sha256(str(usrTxt).encode('utf-8'))
        print(hasher.hexdigest())
    else:
        print("Invalid hash type.")
		

else:
	print("Invalid input at: file import.")
