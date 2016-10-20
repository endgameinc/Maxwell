import sys
import os
import uuid
import time
import pika
import msgpack

class RMQChannel:
    def __init__(self, rmqServer, channelName):
        self.rmqServer = rmqServer
        self.channelName = channelName
        
    def connect(self):
        for x in xrange(0,20):
            # Ephemeral port re-use of snapshots leads to this bizzare behavior
            try:
                self.connection = pika.BlockingConnection(pika.ConnectionParameters(host=self.rmqServer))
                break
            except pika.exceptions.ConnectionClosed:
                if x == 19:
                    raise
        args = {"x-max-priority":10}            
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue=self.channelName, arguments=args)
            
    def close(self):
        self.channel.close()
        self.connection.close()
    
    def send(self, msg):
        data = msgpack.packb(msg)
        self.channel.basic_publish(exchange='',routing_key=self.channelName, body=data, properties=pika.BasicProperties(priority=2))
        
skip = 0
total = 100000
f = open("1m.txt","r")
x = 0
sites = ""
RMQ_SERVER = '127.0.0.1'
rmq = RMQChannel(RMQ_SERVER,'maxwell_queue')
rmq.connect()

for line in f.readlines():
    if skip > 0:
        skip -= 1
        continue
    line = line.rstrip()
    x = x + 1
    if (x % 5) == 1:
        sites = "http://" + line
    elif x % 5 == 0:
        sites = sites + "," + "http://" + line
        print sites
        msg = {}
        msg['plugin'] = 'flux'
        msg['flux'] = {}
        msg['flux']['uuid'] = str(uuid.uuid4())
        msg['flux']['url'] = sites
        rmq.send(msg)
        time.sleep(0.05)
    else:
        sites = sites + "," + "http://" + line
    
    if x >= total:
        break
        
rmq.close()