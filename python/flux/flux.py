import sys
import os
import subprocess
import time
import csv
import re
import shutil
import traceback
import msgpack
import base64
import datetime
import json
import pika
import win32api
import win32con
import signal

def WriteRegValue(hiveKey, key, name, data, typeId=win32con.REG_SZ):
    """ Write one value to Windows registry. If 'name' is empty string, writes default value.
        Creates subkeys as necessary"""
    try:
        keyHandle = win32api.RegOpenKeyEx(hiveKey, key, 0, win32con.KEY_ALL_ACCESS)
        win32api.RegSetValueEx(keyHandle, name, 0, typeId, data)
        win32api.RegCloseKey(keyHandle)
    except Exception, e:
        print "WriteRegValue failed:", hiveKey, name, e
        
class RMQStatus:
    def __init__(self, uuid, rmqServer):
        self.uuid = uuid
        self.rmqServer = rmqServer
        
    def connect(self):
        for x in xrange(0,20):
            # Ephemeral port re-use of snapshots leads to this bizzare behavior
            try:
                self.connection = pika.BlockingConnection(pika.ConnectionParameters(host=self.rmqServer))
                break
            except pika.exceptions.ConnectionClosed:
                if x == 19:
                    raise
                    
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue='maxwell_status')
            
    def close(self):
        self.channel.close()
        self.connection.close()
    
    def SendStatus(self, status):
        print "Sending status: %s" % status
        msg = {}
        msg['uuid'] = self.uuid
        msg['plugin'] = 'flux'
        msg['status'] = status
        
        data = msgpack.packb(msg)
        
        self.channel.basic_publish(exchange='',routing_key='maxwell_status', body=data)
        
if __name__ == "__main__":
    
    # Load proxy if present
    arg = base64.b64decode(sys.argv[1])
    job = json.loads(arg)
    
    # Update local time
    if job.has_key('datetime'):
        date = datetime.datetime.strptime(job['datetime'], "%Y%m%dT%H:%M:%S")
        win32api.SetSystemTime(date.year,date.month,0,date.day,date.hour,date.minute,date.second,0)
        
    rmqStatus = RMQStatus(job['uuid'], job['rmqServer'])
    rmqStatus.connect()
    
    # Send initial status
    rmqStatus.SendStatus("started")
    
    start = time.time()
    
    # Start Pipe Server
    pServer = subprocess.Popen([sys.executable, 'pipeServer.py', job['uuid'], job['rmqServer']]) 
        
    # Move flux to c:\flux.dll
    try:
        os.rename("flux32.dll", r"c:\flux32.dll")
    except:
        pass
    try:
        os.rename("flux64.dll", r"c:\flux64.dll")
    except:
        pass
    
    WriteRegValue(win32con.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", r"c:\flux32.dll", win32con.REG_SZ)
    
    # Launch TcpDump
    dump = subprocess.Popen(['tdump.exe', '-i', '3', '-w', r'c:\traffic.pcap', 'not port 9000 and not port 5672 and not port 22']) 
    time.sleep(2)
    
    # Run Target        
    sites = job['url'].split(",")
    for site in sites:
        os.startfile(site)

    try:
        os.mkdir(r'c:\drop')
    except:
        print "Error creating drop directory"

    # Sleep for X time
    # 70
    time.sleep(60)
    
    # kill TcpDump
    dump.kill()
    
    # send pcap to result server
    t1 = time.time()
    try:
        msg = {}
        msg['plugin'] = "flux"
        pipe = os.open("\\\\.\\pipe\\Maxwell",os.O_BINARY|os.O_WRONLY)
        f = open(r'c:\traffic.pcap',"rb")
        msg['pcapData'] = f.read()
        f.close()
        data = msgpack.packb(msg)
        print "pack",time.time()-t1
        t1 = time.time()
        os.write(pipe,data)
        os.close(pipe)
    except:
        traceback.print_exc()
    
    print "Time to send traffic:", time.time()-t1
    
    time.sleep(5)
    
    try:
        os.remove(r'c:\traffic.pcap')
    except:
        traceback.print_exc()
        
    # Send done msg to result server
    try:
        msg = {}
        msg['plugin'] = "flux"
        msg['status'] = 'finished'
        pipe = os.open("\\\\.\\pipe\\Maxwell",os.O_BINARY|os.O_WRONLY)
        data = msgpack.packb(msg)
        os.write(pipe,data)
        os.close(pipe)
    except:
        traceback.print_exc()
        
    time.sleep(1)
    
    # kill IE
    kill_ie = subprocess.Popen(['taskkill', '/f', '/im', 'iexplore.exe']) 
    kill_ie.communicate()
    
    # terminate pipeServer
    pServer.terminate()
         
    # Send finished status to controller
    rmqStatus.SendStatus("finished")
    
    rmqStatus.close()
    
    print "Total plugin time: %d" % (time.time() - start)

    

