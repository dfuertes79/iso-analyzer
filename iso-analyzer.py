#!/usr/bin/python

import isoparser
import hashlib
import magic
import requests
import time
import os

from optparse import OptionParser

VT_API = ''
DUMP_FILES = False
VT_DELAY = 16
EXECUTABLE_FILE_LIST = {}

def parsecontent(filename):

    print '[+] Parsing ISO file for suspicious content: ' + filename
    parsediso = isoparser.parse(filename)

    print '[+] Looking for artifacts....'
    if parsediso.root.children:
        parsefilecontent(parsediso.root)

def parsefilecontent(node):

    for child in node.children:
        if child.is_directory:
            parsefilecontent(child)
        else:
            extractdata(child)

def extractdata(node):
    global EXECUTABLE_FILE_LIST

    sha256sum = hashlib.sha256(node.content).hexdigest()
    filetype = magic.from_buffer(node.content)

    print '\n[+] ------------------ FILE FOUND ------------------'
    print '[-] File name: ' + node.name
    print '[-] File Type: ' + filetype
    print '[-] SHA256: ' + sha256sum

    #Keep executable files
    if 'executable' in filetype:
        EXECUTABLE_FILE_LIST[sha256sum] = [node.name,filetype, node.content]




def processexecutables(isofile):

    print '\n\n\n[+] Checking files that allow execution with VT.... '

    dirname = os.path.basename(isofile)
    if DUMP_FILES:
        try:
            os.stat(dirname)
        except:
            print '[+] Executable files dumped in directory: ' + dirname + '/'
            os.mkdir(dirname)

    i = 0
    for sha256 in EXECUTABLE_FILE_LIST:

        if i != 0:
            # Apply delay for VT API limits
            print '\n[+] Applying delay of ' + str(VT_DELAY) + ' seconds for VT rate limits......\n'
            time.sleep(VT_DELAY)
        i += 1

        print '\n[+] ------------------ FILE ANALYSIS ------------------'
        print '[-] File name: ' + EXECUTABLE_FILE_LIST[sha256][0]
        print '[-] File Type: ' + EXECUTABLE_FILE_LIST[sha256][1]
        print '[-] SHA256: ' + sha256
        checkvt(sha256)
        if DUMP_FILES:
            dumpfile(dirname, EXECUTABLE_FILE_LIST[sha256][0],EXECUTABLE_FILE_LIST[sha256][2])


def checkvt(sha256sum):

    params = {'apikey': VT_API , 'resource': sha256sum}

    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "python tool, isoparse"
    }

    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                            params=params, headers=headers)
    if response.status_code == 200:
        json_response = response.json()
        #Print data: positives and results per engine
        if json_response['response_code'] == 0:
            print '[-] Hash not in VT '
        else:
            print '[+] Positive Detections: ' + str(json_response['positives'])
            for scan in json_response['scans']:
                if json_response['scans'][scan]['detected']:
                    print '[-] Engine: ' + scan + ' Result: ' + json_response['scans'][scan]['result']

    return

def dumpfile(directory, dname, content):

        try:
            destfile = open(directory + '/' + dname, 'w')
            destfile.write(content)
            destfile.close()
        except Exception, e:
            print 'ERROR writing files to disk: ' + directory + '/' + dname
            print e

        finally:
            return

if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option('-f', '--file', dest = 'isofile', help = 'ISO file to analyze')
    parser.add_option('-v', '--virustotal', dest = 'vtapi', help='Enable and provide Virust Total API to check coverage for hashes')
    parser.add_option('-d', '--dump', action='store_true', dest= 'dumpfiles', help='Automatically dump files that can be executed')
    parser.add_option('-t', '--delay', type=int, dest='requestdelay', help='Delay between VT queries when -v option has been expecified. When not specified, it defaulst to 16s to respect VT public API rate limits')
    options,args = parser.parse_args()

    if not options.isofile:
        print 'Provide an input ISO filename'
        parser.print_help()
        exit(0)

    if options.requestdelay:
        VT_DELAY = options.requestdelay

    if options.dumpfiles:
        DUMP_FILES = True

    isofile = options.isofile
    VT_API = options.vtapi
    DUMP_FILES = options.dumpfiles

    parsecontent(isofile)
    processexecutables(isofile)




