import re
import json
import traceback
 
class Filter():
    
    def __init__(self):
        self.msgs = {}
        self.rules = []
        self.LoadRules()

    def filter(self, msg):
        saveMsg = True
        
        # Don't drop duplicate NtWriteFile messages
        if msg.has_key("function"):
            if msg["function"] == "NtWriteFile":
                saveMsg = False
                
        if msg.has_key("pcapData"):
            return False
            
        # Check if this message is a duplicate
        # In the future, we might want to log all msgs regardless
        if saveMsg:
            msgStr = str(msg)
            if self.msgs.has_key(msgStr):
                #print "Dupe"
                return True
            else:
                # save it for later checks
                self.msgs[msgStr] = None
                
        if self.IsItemWhitelisted(msg):
            # We want to silently pass through dropped files
            if msg["function"] == "NtWriteFile":
                msg['Filter'] = True
                return False
                
            #print "Whitelist"
            return True
        
        return False
                
    def IsItemWhitelisted(self, msg):
        for rule in self.rules:
            found = True
            for key in rule:
                if not msg.has_key(key):
                    found = False
                    break
                    
                type, ruleVal = rule[key]
                
                if type == 0:
                    # str equal type
                    if msg[key] != ruleVal:
                        found = False
                        break
                        
                elif type == 1:
                    # str find type
                    if msg[key].find(ruleVal) < 0:
                        found = False
                        break
                        
                elif type == 2:
                    # re type
                    match = re.search(ruleVal,msg[key])
                    if not match:
                        found = False
                        break
                        
            # if every key had a match     
            if found:
                return True
                
        return False
        
    def LoadRules(self):
        print "Loading rules.."
        lines = open("fluxFilter.txt","rb").readlines()
        for line in lines:
            line = line.rstrip()
            if len(line) == 0:
                continue
            if line[:1] == "#":
                continue
            try:
                rule = json.loads(line, object_hook=self.ascii_encode_dict)
                self.rules.append(rule)
            except:
                traceback.print_exc()
        print "Loaded %d rules" % len(self.rules)
     
    def ascii_encode_dict(self, data):
        ascii_encode = lambda x: x.encode('ascii') if isinstance(x, unicode) else x 
        return dict(map(ascii_encode, pair) for pair in data.items())  
    