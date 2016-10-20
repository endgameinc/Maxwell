import logging
import json
from elasticsearch import Elasticsearch
import os
import pika
import msgpack
import datetime

ESHost = "http://127.0.0.1:9200"
RMQSERVER = "127.0.0.1"


class RMQChannel:
    def __init__(self, rmqServer, channelName):
        self.rmqServer = rmqServer
        self.channelName = channelName
        
    def connect(self):
        self.connection = pika.BlockingConnection(pika.ConnectionParameters(host=self.rmqServer))
        args = {"x-max-priority":10}            
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue=self.channelName, arguments=args)
            
    def close(self):
        self.channel.close()
        self.connection.close()
    
    def send(self, msg):
        data = msgpack.packb(msg)
        self.channel.basic_publish(exchange='',routing_key=self.channelName, body=data, properties=pika.BasicProperties(priority=5))
        
class MaxwellDashboard():
    def __init__(self):
        self.esHost = ESHost
        self.es = Elasticsearch(self.esHost)

    def PP(self,event):
        if event['function'] == "NtCreateUserProcess":
            return " ".join((event['process'],event['function'],event['ImagePathName'],event['CommandLine']))
        elif event['function'] == "oredHandler":
            if event.has_key('EAF'):
                return " ".join((event['process'],event['EAF'],"Source:",event['ModSource'],"Target:",event['ModTarget']))
            elif event.has_key('ExceptionCode'):
                return " ".join((event['process'],'Exception',"Source:",event['Module'],"Code:",event['ExceptionCode']))
        elif event['function'] == "NtWriteFile":
            return " ".join((event['process'],event['function'],"Path:",event['FileName']))
        elif event['function'] == "NtSetValueKey":
            return " ".join((event['process'],event['function'],event['KeyPath'],'->',event['KeyValue']))
        elif event['function'] == 'Main':
            return " ".join((event['process'],event['WerFault']))
        elif event['function'] == 'NtFreeVirtualMemory':
            return " ".join((event['process'],event['function'],'RegionBase',event['RegionBase']))
        elif event['function'] == 'NtQueryAttributesFile' or event['function'] == 'NtCreateFile' or event['function'] == 'NtOpenKeyEx':
            return " ".join((event['process'],"VMDetect", event['VMDetect']))
        else:
            print event
            raise Exception("Unknown Function: %s" % event['function'])
    
    def QueueSite(self, url, channel="maxwell_queue"):
        if url[:7] == "http://":
            rmq = RMQChannel(RMQ_SERVER, channel)
            rmq.connect()
            msg = {}
            msg['plugin'] = 'flux'
            msg['flux'] = {}
            msg['flux']['uuid'] = str(uuid.uuid4())
            msg['flux']['url'] = url
            rmq.send(msg)
            rmq.close()
            return "Submitted"
        else:
            return "Invalid URL"
            
    def TotalJobs(self):
        query =  {'query': { 'constant_score' : { 'filter' : { 'term': 
        {'status':'started'}
        } } } }
        results = self.es.search(index="m_index",doc_type="maxwell", body=query)
        return results['hits']['total']
        
    def Performance(self):
        query =  {'query': { 'constant_score' : { 'filter' : { 'bool': { 'must' : [    
            {'term':  {'status':'started'} },
            {'range': {'timestamp':{"gt" : "now-1h"} } },   
        ] } } } } }
        results = self.es.search(index="m_index",doc_type="maxwell", body=query, size=10)
        #for hit in results['hits']['hits']:
        #    print hit
        return results['hits']['total']
    
    def GetHits(self):
        query =  {'query': { 'constant_score' : { 'filter' : { 'bool': { 
            'must' : [    
            {'range': {'timestamp':{"gt" : "now-1w"} } },
            {'term':  {'status':'malicious'} },
            ],
        } } } } }
        results = self.es.search(index="m_index",doc_type="maxwell", body=query, size=100, sort="timestamp:desc")
        uuids = []
        for hit in results['hits']['hits']:
            uuid = hit['_source']['uuid']
            if uuid not in uuids:
                uuids.append(uuid)
        return uuids
        
    def GetBasicJobInfo(self, uuid):
        info = {}
        results = self.es.search(index="m_index",doc_type="maxwell", q='uuid:"%s" AND status:started'%(uuid))
        if results['hits']['total'] < 1:
            return
        hit = results['hits']['hits'][0]
        results = self.es.search(index="m_index",doc_type="maxwell", q='uuid:"%s"' %(uuid))
        eventCount = results['hits']['total']
        date = datetime.datetime.strptime(hit['_source']['timestamp'][:19], "%Y-%m-%dT%H:%M:%S")
        info['timestamp'] = date.strftime("%m/%d %H:%M")
        info['uuid'] = uuid
        info['url'] = hit['_source']['url']
        info['eventCount'] = eventCount - 4
        return info
    
    def PostProcessFromUUID(self, uuid):
        # ToDo, grab latest post process
        results = self.es.search(index="m_index",doc_type="maxwell", q='uuid:"%s" AND postProcess:*'%(uuid))
        if results['hits']['total'] < 1:
            return ""
        hit = results['hits']['hits'][0]['_source']['postProcess']
        return hit
        
    def GetEventsByUUID(self, uuid):
        query =  {'query': { 'constant_score' : { 'filter' : { 'bool': { 
            'must' : [    
            {'query_string':  {'query':'uuid:"'+ uuid + '"'} },
            {'exists':  {'field':'function'} },
            ],
            #'must_not' : [    
            #{'exists':  {'field':'status'} },
            #],
        } } } } }
        results = self.es.search(index="m_index",doc_type="maxwell", body=query, size=1000, sort="timestamp:asc")
        
        events = ""
        dedup = {}
        for hit in results['hits']['hits']:
            event = self.PP(hit['_source'])
            if not dedup.has_key(event):
                events += event + "\r\n"
                dedup[event] = None
        return events
        
    def DeleteResults(self, uuid):
        #delete by query not supported? results = self.es.delete_by_query(index="m_index",doc_type="maxwell", q='uuid:"%s"'%(uuid))
        results = self.es.search(index="m_index",doc_type="maxwell", q='uuid:"%s"'%(uuid), size=1000)
        for hit in results['hits']['hits']:
            id = hit['_id']
            self.es.delete(index="m_index",doc_type="maxwell", id=id)
            
    def EnumDroppedFiles(self, uuid):
        dropped_files = ""
        for root, dirs, files in os.walk(os.path.join('extracted',uuid)):
            for name in files:
                path = os.path.join(root, name).replace(os.path.join('extracted',uuid), "")
                dropped_files += path + "\r\n"
        return dropped_files

if __name__ == "__main__":

    dash = MaxwellDashboard()
    print "Total jobs", dash.TotalJobs()
       
    perHr = dash.Performance()
    print "Performance: %d jobs per hr" % (perHr)
    print "Performance: %d sites per day (at 5 per job)" % (perHr * 24 * 5)
    hits = dash.GetHits()
    for uuid in hits:
        print "-"*30
        print dash.GetBasicJobInfo(uuid)
        print dash.PostProcessFromUUID(uuid)
        print ""
        print dash.GetEventsByUUID(uuid)
        print ""
        print "Dropped Files:\r\n" + dash.EnumDroppedFiles(uuid)
        
