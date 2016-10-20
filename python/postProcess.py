#!/usr/bin/python

import sys
import re
import subprocess
import yara
import zlib
import pylzma
import os
import shutil
import traceback

def ParseFile(data, name):
    
    rule = yara.compile("rules.yr")
    matches = rule.match(data=data)
    if len(matches) > 0:
        for hit in matches['main']:
            print name,hit['rule']
            
    if data[:3] == 'CWS':
        #print "Zlib Compressed"
        try:
            new = 'FWS' + data[3:8] + zlib.decompress(data[8:])
        except:
            print "zlib error "
            return
        ParseFile(new, name)
        
    elif data[:3] == 'ZWS':
        #print "lzma compressed"
        try:
            new = 'FWS' + data[3:8] + pylzma.decompress_compat(data[12:])
        except:
            print "pylzma error "
            return
        ParseFile(new, name)
        
    elif data[:3] == "GET":
    
        # Angler
        search = re.search(r'(GET /.{1,25}/index.php\?PHPSESSID=.{1,6}&action=.{12}.{1,512})\r\n\r\n',data,re.S)
        if search:
            print "Angler GET",name
            print search.group(1)

        search = re.search(r'(GET .{0,100}/.{1,25}/viewtopic.php\?t=.{1,6}&f=.{12}.{1,512})\r\n\r\n',data,re.S)
        if search:
            print "Angler GET",name
            print search.group(1)
            
        search = re.search(r'(GET .{0,100}/.{1,25}/viewforum.php\?f=.{1,6}&sid=.{12}.{1,512})\r\n\r\n',data,re.S)
        if search:
            print "Angler GET",name
            print search.group(1)

        search = re.search(r'(GET .{0,100}/.{1,25}/search.php\?keywords=.{1,6}&fid0=.{12}.{1,512})\r\n\r\n',data,re.S)
        if search:
            print "Angler GET",name
            print search.group(1)
            
        search = re.search(r'(GET .{0,100}/topic/[0-9]{4,12}(-[a-z]{3,20}){3,10}/ HTTP.{1,512})\r\n\r\n',data,re.S)
        if search:
            print "Angler GET",name
            print search.group(1)
        
        # RIG
        search = re.search(r'(GET .{0,100}/\?[a-zA-Z0-9]{15}=[a-zA-Z0-9_-]{100,200} HTTP.{1,512})\r\n\r\n',data,re.S)
        if search:
            print "RIG GET",name
            print search.group(1)
        
        # Eltest Gate
        search = re.search(r'(GET /[a-z0-9\-]{80,150}/[a-z]{1,20}\.html HTTP.{1,512})\r\n\r\n',data,re.S)
        if search:
            print "EItest GET",name
            print search.group(1)
            
        # Magnitude
        search = re.search(r'(GET .{0,100}/\?[a-z0-9]{38} HTTP.{1,512})\r\n\r\n',data,re.S)
        if search:
            print "Magnitude GET",name
            print search.group(1)
            
        # Neutrino   
        search = re.search(r'(GET.{1,512}Media Center PC 6\.0; rv.{1,100})\r\n\r\n',data,re.S)
        if search:
            print "Neutrino GET",name
            print search.group(1)
    else:        
        # AfraidGate
        search = re.search(r'^(document\.write\(.{200,400}i\'\+\'frame.{5,20}\))',data,re.S)
        if search:
            print "AfraidGate",name
            print search.group(1)
        
        # Pseudo Darkleech
        search = re.search(r'(<span id=\".{1,20} style=\"display:none\">).{3000,10000}</span>',data,re.S)
        if search:
            print "Psuedo Darkleech",name
            print search.group(1)
            
def decode_chunked(data):
    offset = 0
    encdata = ''
    newdata = ''
    offset = data.index("\r\n\r\n") + 4 # get the offset 
    # of the data payload. you can also parse content-length header as well.
    encdata =data[offset:]
    try:
        while (encdata != ''):
            off = int(encdata[:encdata.index("\r\n")],16)
            if off == 0:
                break
            encdata = encdata[encdata.index("\r\n") + 2:]
            newdata = "%s%s" % (newdata, encdata[:off])
            encdata = encdata[off+2:]
                             
    except:
       print "Exception! decode_chunk"
       return ""
    return newdata
    
def ProcessPCAP(file, path):
    try:
        pcapFile = os.path.join(path, file)
        if os.path.isfile(pcapFile) == False:
            return
            
        flowDir = os.path.join(path, "flow")
        if os.path.exists(flowDir) == False:
            os.mkdir(flowDir)
            
        subprocess.call(['tcpflow','-r',pcapFile,'-o',flowDir, '-a', '-d', '0'])
        
        for root, dirs, files in os.walk(flowDir):
            for name in files:
                path = os.path.join(root, name)
                try:
                    file_data = open(path, "rb").read()
                    ParseFile(file_data,name)
                except:
                    print "Error " + path
                    traceback.print_exc()
                    
                    
        shutil.rmtree(flowDir)
    except:
        traceback.print_exc()
        print "Exception ProcessPCAP"
        
if __name__ == "__main__":
    outDir = sys.argv[1]
    
    ProcessPCAP("traffic.pcap", outDir)
    
    for root, dirs, files in os.walk(outDir):
        for name in files:
            path = os.path.join(root, name)
            if name == "traffic.pcap":
                pass
            else:
                try:
                    f = open(path, "rb")
                    file_data = f.read()
                    ParseFile(file_data,name)
                    f.close()
                    if path[-4:] == '.exe':
                        os.rename(path,path+'.bad')
                except:
                    print traceback.print_exc()
                    print "Error accessing " + path
    
