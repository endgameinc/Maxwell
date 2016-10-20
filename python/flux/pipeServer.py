import logging
import threading
import msgpack
import json
import struct
import ctypes
import sys
import importlib
import traceback
import time
import pika
import signal

from uuid import uuid4

from ctypes import windll
from ctypes import create_string_buffer, c_uint, byref, sizeof, Structure
DWORD       = ctypes.c_uint32
LPVOID      = ctypes.c_void_p
BOOL        = ctypes.c_int
LPSTR       = ctypes.c_char_p
LPWSTR      = ctypes.c_wchar_p
GENERIC_READ                     = 0x80000000
GENERIC_WRITE                    = 0x40000000
CREATE_ALWAYS                    = 2
FILE_ATTRIBUTE_NORMAL            = 0x00000080
PIPE_ACCESS_INBOUND = 0x1
PIPE_ACCESS_OUTBOUND = 0x2
PIPE_ACCESS_DUPLEX = 0x3
PIPE_TYPE_MESSAGE = 0x4
PIPE_REJECT_REMOTE_CLIENTS = 0x8
PIPE_READMODE_MESSAGE = 0x2
PIPE_WAIT = 0
PIPE_UNLIMITED_INSTANCES = 0xff
NMPWAIT_USE_DEFAULT_WAIT = 0
INVALID_HANDLE_VALUE = -1
ERROR_BROKEN_PIPE = 109
ERROR_MORE_DATA = 234

BUFSIZE = 0x500000

resultHost = ""
port = 0
uuid = ""

filters = {}

''' ACL Stuff '''
# typedef struct _SECURITY_ATTRIBUTES {
#     DWORD nLength;
#     LPVOID lpSecurityDescriptor;
#     BOOL bInheritHandle;
# } SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;
class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ('nLength',                 DWORD),
        ('lpSecurityDescriptor',    LPVOID),
        ('bInheritHandle',          BOOL),
    ]

class TRUSTEE(Structure):
    _fields_ = [
        ('pMultipleTrustee',    LPVOID),
        ('MultipleTrusteeOperation',   DWORD),
        ('TrusteeForm',  DWORD),
        ('TrusteeType', DWORD),
        ('SID', LPVOID),
    ]
# typedef struct _EXPLICIT_ACCESS_W
# {
#     DWORD        grfAccessPermissions;
#     ACCESS_MODE  grfAccessMode;
#     DWORD        grfInheritance;
#     TRUSTEE_W    Trustee;
# } EXPLICIT_ACCESS_W, *PEXPLICIT_ACCESS_W, EXPLICIT_ACCESSW, *PEXPLICIT_ACCESSW;
class EXPLICIT_ACCESS(Structure):
    _fields_ = [
        ('grfAccessPermissions',    DWORD),
        ('grfAccessMode',   DWORD),
        ('grfInheritance',  DWORD),
        ('Trustee', TRUSTEE),
    ]
      
def Everyone_SecurityAttributes():
    '''
    This function creates the security attributes needed to create an object with READ/WRITE permissions to the everyone group
    '''
    sa = SECURITY_ATTRIBUTES()
    ACL = create_string_buffer(28)
    SD = create_string_buffer(40) #size is 20 for x86
    ACL.raw = "\x02\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x14\x00\x00\x00\x00\xc0\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00"
    
    if 8 == struct.calcsize("P"):
        # x64
        addr = struct.pack("q", ctypes.addressof(ACL))
        SD.raw = "\x01\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + addr
        sa.nLength = 0x18
    else:
        # x86
        addr = struct.pack("l", ctypes.addressof(ACL))
        SD.raw = "\x01\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + addr
        sa.nLength = 0xC #0xC for x86
    
    sa.lpSecurityDescriptor = ctypes.cast(SD, LPVOID)
    sa.bInheritHandle = False
    
    lpSecurityAttributes = ctypes.pointer(sa)
    return lpSecurityAttributes
    
    '''
    _CreateFileA = windll.kernel32.CreateFileA
    _CreateFileA.argtypes = [LPSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, DWORD]
    _CreateFileA.restype  = DWORD

    lpSecurityAttributes = ctypes.pointer(sa)
    
    hFile = _CreateFileA("testfile", GENERIC_READ | GENERIC_WRITE, 0, lpSecurityAttributes, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0)
    print hFile
    '''
    
    
class PipeReceiver(threading.Thread):
    def __init__(self, pipeHandle):
        threading.Thread.__init__(self)
        self.daemon = True
        self.pipeHandle = pipeHandle

    def MsgIn(self, data):
        #print "Recieved msg"
        
        try:
            msg = msgpack.unpackb(data)
        except:
            traceback.print_exc()
            return
        
        if not filters.has_key(msg['plugin']):
            try:
                plugFilter = importlib.import_module(msg['plugin'] + "Filter")
                filters[msg['plugin']] = plugFilter.Filter()
            except ImportError:
                print "Error importing filter for %s" % msg['plugin']
                filters[msg['plugin']] = None
        
        
        if filters[msg['plugin']] != None:
            result = filters[msg['plugin']].filter(msg)
            # print "FilterResult",result
            if result:
                # This msg has been filtered
                return
                
        '''        
        try:
            print json.dumps(msg, ensure_ascii=False, sort_keys=True, indent=4, separators=(',', ': '))
        except:
            print msg  
        '''
        
        # Add UUID to message
        msg['uuid'] = uuid
        
        # Add datetime, milliseconds since epoch for elasticsearch
        # msg['timestamp'] = str(int(time.time()*1000))     
        
        data = msgpack.packb(msg)
        
        try:
            channel.basic_publish(exchange='',routing_key='maxwell', body=data)
        except:
            traceback.print_exc()
            # Results server down?
            pass
        
    def run(self):
        data = ""
        buf = create_string_buffer(BUFSIZE)
        bytes_read = c_uint()
        pid = c_uint()
        print "New receiver thread"
        while True:
            retVal = windll.kernel32.ReadFile(self.pipeHandle,
                                        byref(buf), sizeof(buf),
                                        byref(bytes_read), None)
            if retVal:
               data += buf.raw[:bytes_read.value]
               self.MsgIn(data)
               data = ""
            elif windll.kernel32.GetLastError() == ERROR_MORE_DATA:
                data += buf.raw[:bytes_read.value]
            elif windll.kernel32.GetLastError() == ERROR_BROKEN_PIPE:
                break
            else:
                print "Error reading from pipe",windll.kernel32.GetLastError()
                break
 
class GracefulExit():
  def __init__(self):
    self.exit_now = False
    signal.signal(signal.SIGINT, self.exit_gracefully)
    signal.signal(signal.SIGTERM, self.exit_gracefully)
    
  def exit_gracefully(self,signum, frame):
    print "signal"
    self.exit_now = True
   
def SendDone():
    msg['uuid'] = uuid
    msg['plugin'] = 'flux'
    msg['status'] = 'finished'
    data = msgpack.packb(msg) 
    try:
        channel.basic_publish(exchange='',routing_key='maxwell', body=data)
    except:
        traceback.print_exc()
        # Results server down?
        pass
            
class PipeServer(threading.Thread):

    def __init__(self, pipeName):
        threading.Thread.__init__(self)
        self.pipeName = pipeName
        self.active = True
        self.daemon = True
        
    def run(self):
        print "Listening on %s" % self.pipeName
        while self.active:
            pipeHandle = windll.kernel32.CreateNamedPipeA(
                    self.pipeName, PIPE_ACCESS_INBOUND,
                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    PIPE_UNLIMITED_INSTANCES, 0, BUFSIZE, 0, 0) #Everyone_SecurityAttributes())
            
            if INVALID_HANDLE_VALUE == pipeHandle:
                print "Error creating pipe",windll.kernel32.GetLastError()
                continue
                
            if windll.kernel32.ConnectNamedPipe(pipeHandle, None) or windll.kernel32.GetLastError() == ERROR_PIPE_CONNECTED:
                handler = PipeReceiver(pipeHandle)
                handler.daemon = True
                handler.start()
            else:
                windll.kernel32.CloseHandle(pipeHandle)
        
    def stop(self):
        active = False;
        
if __name__ == "__main__":
    uuid = sys.argv[1]
    rmqServer = sys.argv[2]
    
    for x in xrange(0,20):
        # Ephemeral port re-use of snapshots leads to this bizzare behavior
        try:
            connection = pika.BlockingConnection(pika.ConnectionParameters(host=rmqServer))
            break
        except pika.exceptions.ConnectionClosed:
            if x == 19:
                raise
                
    channel = connection.channel()
    channel.queue_declare(queue='maxwell')
            
    pipeServer = PipeServer(r'\\.\PIPE\Maxwell')
    pipeServer.start()
    
    exitSignal = GracefulExit()
    while not exitSignal.exit_now:
        try:
            time.sleep(1)
        except:
            pass
        
    print "Shutting down"
    SendDone()
    connection.close()
    print "pipeServer done"
    
    