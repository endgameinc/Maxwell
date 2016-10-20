#!/usr/bin/python

import SocketServer
import struct
import msgpack
import getpass
import traceback
import smtplib
import json
import subprocess
import os
import shutil
import time
import sys
from elasticsearch import Elasticsearch
import datetime
import pika

from uuid import uuid4

results = {}
rmqServer = '127.0.0.1'
ESHost = "http://127.0.0.1:9200"

def HandleDroppedFile(msg):
    if not msg.has_key('FileData') or not msg.has_key('FileName') or not msg.has_key('uuid') :
        print "Invalid parameter"
        return
    
    i = msg['FileName'].rfind("\\")
    
    path = msg['FileName'][1:i]    
    file = msg['FileName'][i+1:]

    path = path.replace("\\", os.path.sep)
    path = os.path.join("extracted", msg['uuid'], path)
    
    if not os.path.exists(path):
        os.makedirs(path)
    
    try:
        open(os.path.join(path,file), "ab").write(msg['FileData'])
    except:
        traceback.print_exc()
        
    del msg['FileData']
    
def HandlePCAP(msg):
    if not msg.has_key('pcapData') or not msg.has_key('uuid') :
        print "Invalid parameter"
        return
    
    path = ""
    file = "traffic.pcap"

    path = path.replace("\\", os.path.sep)
    path = os.path.join("extracted", msg['uuid'], path)
    
    if not os.path.exists(path):
        os.makedirs(path)
    
    open(os.path.join(path,file), "wb").write(msg['pcapData'])
    
def PostProcess(msgs):
    post_txt = ""
    thisUuid = msgs[0]['uuid']
    try:
        jsonOutput = json.dumps(msgs, ensure_ascii=False, sort_keys=True, indent=4, separators=(',', ': '))
    except:
        traceback.print_exc()
        jsonOutput = str(msgs)
        
    try:
        outDir = os.path.join("extracted", thisUuid)
        if not os.path.exists(outDir):
            os.makedirs(outDir)
        
        postFile = os.path.join("extracted", thisUuid, "post.txt")
        f = open(postFile,"wb")
        
        subprocess.call([sys.executable, 'postProcess.py', outDir],stdout=f)
        f.close()
        post_txt = open(postFile,"rb").read()
        
        outFile = open('results' + os.sep + thisUuid, 'wb')
        outFile.write(post_txt + "\r\n" + jsonOutput)
        outFile.close()
    except:
        print "Post Processing Error"
        post_txt = "Post Processing Error"
        post_txt += "\r\n"
        post_txt += traceback.format_exc()
 
    return post_txt
    
def IndexMsg(msg):
    msg['timestamp'] = datetime.datetime.utcnow()
    try:
        es = Elasticsearch(ESHost)
        result = es.index(index="m_index",doc_type="maxwell", body=msg)
    except:
        traceback.print_exc()
    del msg['timestamp']

def IndexPostResult(msg, result_txt):
    newMsg = {}
    newMsg['uuid'] = msg['uuid']
    newMsg['plugin'] = msg['plugin']
    newMsg['postProcess'] = result_txt
    IndexMsg(newMsg)
    
def callback(ch, method, properties, body):

    try:
        msg = msgpack.unpackb(body)
    except:
        traceback.print_exc()
        return
        
    if msg.has_key('FileData'):
        # ToDo filter these messages after reception
        HandleDroppedFile(msg)
        if msg.has_key('Filter') and msg['Filter'] == True:
            return
            
    if msg.has_key('pcapData'):
        #print "Received pcap"
        HandlePCAP(msg)
        return
        
    print msg
    
    IndexMsg(msg)
    
    # ToDo ElasticSearch
    if not results.has_key(msg['uuid']):
        results[msg['uuid']] = []
    
    results[msg['uuid']].append(msg)
    
    if msg.has_key('status'):          
        if msg['status'] == "finished" and msg['plugin'] == "flux":
            if len(results[msg['uuid']]) > 2:
                # Alert
                msg['status'] = "malicious"
                IndexMsg(msg)
                result_txt = PostProcess(results[msg['uuid']])
                IndexPostResult(msg, result_txt)
            else:
                # Clean any dropped files
                try:
                    shutil.rmtree(os.path.join("extracted", msg['uuid']))
                except:
                    traceback.print_exc()
                
            del results[msg['uuid']]

if __name__ == "__main__":
   
    connection = pika.BlockingConnection(pika.ConnectionParameters(
            host=rmqServer))
    channel = connection.channel()

    channel.queue_declare(queue='maxwell')

    channel.basic_consume(callback,
                          queue='maxwell',
                          no_ack=True)

    print(' [*] Waiting for messages. To exit press CTRL+C')
    channel.start_consuming()
    