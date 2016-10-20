import xmlrpclib
import time
import sys
from zipfile import ZipFile, ZIP_STORED
from StringIO import StringIO
import os
import thread
import threading
import subprocess
import traceback
from pysphere import VIServer
import re
import datetime
import getpass
import msgpack
import logging
import pika
import json
from elasticsearch import Elasticsearch

logger = logging.getLogger('maxwell')
logger.setLevel(logging.DEBUG)
# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
# create formatter
formatter = logging.Formatter('%(asctime)s %(levelname)s:%(message)s')
# add formatter to ch
ch.setFormatter(formatter)
# add ch to logger
logger.addHandler(ch)

# create file handler
fh = logging.FileHandler('maxwell.log')
fh.setLevel(logging.DEBUG)
# create formatter
formatter = logging.Formatter('%(asctime)s %(levelname)s:%(message)s')
# add formatter to fh
fh.setFormatter(formatter)
# add fh to logger
logger.addHandler(fh)

# Configuration here
MAXTIMEOUT = 200
MasterURL = "http://127.0.0.1:5000"
mutex = threading.Lock()
MAXJOBS_PER_SNAPSHOT = 15
esxUser = r'Insert_Username'
esxPass = r''
esxHost = r'Insert_Esx_IP'
rmqServer = "127.0.0.1"
RMQ_SERVER_JOB = "Insert_RMQ_Server_IP" #5672
ESHost = "http://127.0.0.1:9200"

jobStatus = {}

def log(vm, msg):
    t = str(datetime.datetime.now())
    # or t = time.strftime("%Y-%m-%d %H:%M:%S")
    f = open("log.txt","a")
    f.write("[" + t + "] - [" + vm + "] - " + msg + "\r\n")
    f.close()
    print "[" + t + "] - [" + vm + "] - " + msg
            
def TestConnection(host,port):
    try:
        #print "Testing %s:%s" % (host,port)
        nc = subprocess.Popen(['nc','-w','2','-zv',host,port], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, error = nc.communicate()
        if error.find('succeeded') >= 0:
                return True
        return False
    except:
        traceback.print_exc()
        return False
                
def Connected():
    try:
        ping = subprocess.Popen(['ping','-c','1','google.com'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, error = ping.communicate()
        m = re.search(r'time=(.*?) ms', out)
        if m == None:
            log("Main", "Ping timeout")
            return False
        delay = float(m.group(1))
        log("Main", "Ping - " + str(delay))
        if delay < 100:
            return True
        return False
    except:
        log("Main", "Ping - Unknown Error")
        return False
     
class ESXMachine:
    def __init__(self, Name, Snapshot, OS, IP, userName='max', workQueue='maxwell_queue', rmqServerJob = RMQ_SERVER_JOB, maxJobsPerSnapshot = MAXJOBS_PER_SNAPSHOT):
        self.Name = Name
        self.Snapshot = Snapshot
        self.OS = OS
        self.IP = IP
        self.userName = userName
        self.workQueue = workQueue
        self.rmqServerJob = rmqServerJob
        self.maxJobsPerSnapshot = maxJobsPerSnapshot
        self.status = 'idle'
            
    def GetInfo(self):
        print self.VMXPath
        print self.Snapshot
        print self.OS
        print self.IP
        print self.status
    
    def Connect(self):
        self.server = VIServer()
        self.server.connect(esxHost, esxUser, esxPass)
        self.vm = self.server.get_vm_by_name(self.Name)
            
    def Start(self):
        try:
            logger.debug("%s - Connecting to ESXi" % (self.Name))
            self.Connect()
            logger.debug("%s - Starting VM" % (self.Name))
            self.vm.revert_to_named_snapshot(self.Snapshot)
        except:
            logger.error("%s - Error on Revert - %s" % (self.Name, traceback.format_exc()))
                    
    def Stop(self):
        try:
            logger.debug("%s - Stopping VM" % (self.Name))
            self.vm.power_off()
            self.server.disconnect()
        except:
            logger.error("%s - Error on Stop" % (self.Name))
                   
    def Finish(self):
        mutex.acquire()
        self.Stop()
        mutex.release()
        self.status = 'idle'
        logger.debug("%s - shutdown" % (self.Name))

def callback(ch, method, properties, body):
    logger.debug("Callback")
    try:
        msg = msgpack.unpackb(body)
        print msg
        jobStatus[msg['uuid']] = msg['status']
    except:
        logger.error("Callback error: %s" % (traceback.format_exc()))

def StatusCallback(ch, method, properties, body):
    try:
        msg = msgpack.unpackb(body)
        jobStatus[msg['uuid']] = msg['status']
        logger.debug("Received status: %s - %s" % (msg['uuid'], msg['status']))
    except:
        logger.error("Callback error: %s" % (traceback.format_exc()))
            
class RMQConsumer(threading.Thread):
    def __init__(self, queueName, callback):
        threading.Thread.__init__(self)
        self.queueName = queueName
        self.daemon = True
        
        self.conn = pika.BlockingConnection(pika.ConnectionParameters(
            host=rmqServer))
        self.statusChannel = self.conn.channel()
    
        self.statusChannel.queue_declare(queue=queueName)
         
        self.statusChannel.basic_consume(callback,
                              queue=queueName,
                              no_ack=True)                   
    def run(self):
        logger.debug("Consumer started on queue: %s" % self.queueName)
        self.statusChannel.start_consuming()
 

class RMQChannel:
    def __init__(self, rmqServer, channelName):
        self.rmqServer = rmqServer
        self.channelName = channelName
        
    def connect(self, priority=False):
        for x in xrange(0,20):
            # Ephemeral port re-use of snapshots leads to this bizzare behavior
            try:
                self.connection = pika.BlockingConnection(pika.ConnectionParameters(host=self.rmqServer))
                break
            except pika.exceptions.ConnectionClosed:
                if x == 19:
                    raise
        if priority:
            args = {"x-max-priority":10}           
        else:
            args = {}
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue=self.channelName, arguments=args)
            
    def close(self):
        self.channel.close()
        self.connection.close()
    
    def send(self, msg):
        data = msgpack.packb(msg)
        self.channel.basic_publish(exchange='',routing_key=self.channelName, body=data)
    
    def recv(self):
        method_frame, header_frame, body = self.channel.basic_get(queue=self.channelName, no_ack=True)
        return body
        
def Worker(VM):
    uuid = ""
    env = []
    
    while True:
        try:
            VM.status = 'running'
            VM.Start()

            for x in xrange(0, VM.maxJobsPerSnapshot):
                # grab next job
                queueChannel = RMQChannel(rmqServer, VM.workQueue)
                queueChannel.connect(priority=True)
                while True:
                    body = queueChannel.recv()
                    if body:
                        break
                    logger.debug("%s - work queue is empty" % (VM.Name))
                    time.sleep(15)
                queueChannel.close()
                job = msgpack.unpackb(body)
                    
                plugin = job['plugin']
                uuid = job[plugin]['uuid']
                logger.debug("%s - plugin config - %s" % (VM.Name,str(job[plugin])))
                logger.debug("%s - IP - %s" % (VM.Name,VM.IP))
            
                # send start msg to resultServer
                if plugin == 'flux':
                    resultServer = RMQChannel(rmqServer, "maxwell")
                    resultServer.connect()
                    startMsg = {'plugin':plugin, 'uuid':uuid, 'status':'started', 'url':job[plugin]['url']}
                    if job.has_key('environment'):
                        startMsg['environment'] = job['environment']
                    resultServer.send(startMsg)
                    resultServer.close()
                
                # Update Job
                job[plugin]['datetime'] = datetime.datetime.utcnow().strftime("%Y%m%dT%H:%M:%S")
                job[plugin]['rmqServer'] = VM.rmqServerJob
                
                # copy environment data to host
                if job.has_key('environment'):
                    for env in job['environment']:
                        logger.debug("%s - Copying %s to host" % (VM.Name, env))
                        with open(os.devnull, 'w') as devnull:
                            proc = subprocess.Popen(['scp','-o','UserKnownHostsFile=/dev/null','-o', 'StrictHostKeyChecking=no','-i','maxwell_key', '-r', env, VM.userName+'@'+VM.IP+':desktop/'], stdout=devnull)
                            proc.communicate()
                
                # copy plugin to host
                logger.debug("%s - Copying %s to host" % (VM.Name, plugin))
                with open(os.devnull, 'w') as devnull:
                    proc = subprocess.Popen(['scp','-o','UserKnownHostsFile=/dev/null','-o', 'StrictHostKeyChecking=no','-i','maxwell_key', '-r', plugin, VM.userName+'@'+VM.IP+':desktop/'], stdout=devnull)
                    proc.communicate()
                
                # save job to file, send to host
                logger.debug("%s - Copying job to host" % (VM.Name))
                jobFile = uuid+'.txt'
                f = open(jobFile,"wb")
                f.write(json.dumps(job))
                f.close()
                with open(os.devnull, 'w') as devnull:
                    proc = subprocess.Popen(['scp','-o','UserKnownHostsFile=/dev/null','-o', 'StrictHostKeyChecking=no','-i','maxwell_key', jobFile, VM.userName+'@'+VM.IP+':desktop/job.txt'], stdout=devnull)
                    proc.communicate()
                os.remove(jobFile)
                
                start = time.time()
                timeout = 300
                while True:
                    if jobStatus.has_key(uuid) and jobStatus[uuid] == 'started':
                        logger.debug("%s - Plugin Started after %ds" % (VM.Name, time.time() - start))
                        break
                    if time.time() - start > 30:
                        logger.error("%s - slow vm.. %s" % (VM.Name, VM.IP))
                    if time.time() - start > timeout:
                        logger.error("%s - timeout initializing plugin" % (VM.Name))
                        quit()
                        break
                    time.sleep(1)
                    
                if time.time() - start > 30:
                    logger.error("%s - excessive wait time: %ds" % (VM.Name, time.time() - start))
                    
                if not jobStatus.has_key(uuid) or jobStatus[uuid] != 'started':
                    break
                
                # Wait for job to finish
                maxTime = time.time() + MAXTIMEOUT
                while time.time() < maxTime:
                    if jobStatus[uuid] == "finished":
                        break
                    time.sleep(1)
                
                if time.time() - (maxTime - MAXTIMEOUT) > 120:
                    logger.error("%s - excessive plugin wait time: %ds" % (VM.Name, (time.time() - (maxTime - MAXTIMEOUT))))
                    
                if jobStatus[uuid] == "started":
                    logger.error("%s - timeout waiting for plugin finish" % (VM.Name))
                    quit()
                    break
                elif jobStatus[uuid] == "failed":
                    logger.error("%s - status failed" % (VM.Name))
                    break
                else:
                    logger.debug("%s - finished" % (VM.Name))
                    
                del jobStatus[uuid]
                
                # Detect 
                es = Elasticsearch(ESHost)
                #query =  {'query': { 'term': {'uuid':uuid} } }
                results = es.search(index="m_index",doc_type="maxwell", q='uuid:"'+uuid+'"')
                
                if results['hits']['total'] > 2:
                    logger.debug("%s - malicious!" % (VM.Name))
                    break
        except:
            logger.error("%s - Worker, Unexpected Error - %s" % (VM.Name, traceback.format_exc()))
            quit()
        
        # House keeping
        if jobStatus.has_key(uuid):
            del jobStatus[uuid]
                    
    
if __name__ == '__main__':
    VMs = []
    
    esxPass = getpass.getpass("Enter esx password: ")
     
    #Name, Snapshot, OS, IP):
    VMs.append(ESXMachine('VM_Clone_Name','Snapshot_Name','WIN7','VM_IP'))

        
    statusConsumer = RMQConsumer('maxwell_status', StatusCallback)
    statusConsumer.start()
    
    for VM in VMs:
        thread.start_new_thread(Worker, (VM,))
        
    while True:                
        time.sleep(1)
        
    