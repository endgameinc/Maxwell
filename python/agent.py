import json
import os
import time
import subprocess
import base64
import sys
import traceback

while True:
    try:
        print "Agent running.."

        data = ""
        
        # Loop until job.txt is found
        while os.path.exists("job.txt") == False:
            time.sleep(1)

        print "Received Job"
        
        # Read job.txt
        with open("job.txt","rb") as f:
            data = f.read()
        
        # Decode job from json
        job = json.loads(data)
        
        # execute environment setup
        if job.has_key('environment'):
            for env in job['environment']:
                print env
                os.chdir(env)
                proc = subprocess.Popen([sys.executable, "setup.py"])
                proc.communicate()
                os.chdir('..')
                
        plugin = job['plugin']

        # Pass plugin config as base64 encoded string
        pluginParam = base64.b64encode(json.dumps(job[plugin]))

        os.remove("job.txt")
                
        # Launch plugin
        print "Lauching %s" % plugin
        os.chdir(plugin)
        proc = subprocess.Popen([sys.executable, plugin + ".py", pluginParam])
        proc.communicate()
        os.chdir('..')
        
        print "job finished"
    except:
        traceback.print_exc()
        



