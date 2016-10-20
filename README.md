###Maxwell
Maxwell is an automated system which crawls the web and identifies exploit kit and watering hole activity. It can detect these events with high confidence and perform automated processing to determine which exploit kit was involved. This system can support a variety of research or network defense related initiatives.

###Management code
python/controller.py
Primary script for spinning virtual machines up and down. Receives jobs from the Rabbitmq job queue and sends this information to a worker virtual machine. This script is currently compatible with esxi, but could be extended to other virtualization or cloud platforms.

python/resultsServer.py
Receives events from the virtual machines from the Rabbitmq server. It has 2 main purposes. First, it sends messages to an elasticsearch server for permenant storage. Second, if detects a particular job is malicious, it will launch the post processing routine (postProcess.py).

python/postProcess.py
Processes the PCAP for a given job if it is detected as malicious. First, tcpflow extracts all sessions from the pcap. Next, all files and run through yara to look for known signatures. Finally, certain regular expressions are run over the data to look for known exploit kit traffic patterns.

python/dashboard.py 
Convenience script for querying Maxwell data from the ElasticSearch backend. It can be run from the command line or could be used to build a web interface on top of Maxwell data.

python/addSites.py
Example script to parse a file that contains a list of websites and add them to the Maxwell job queue. 

###VM Code
python/agent.py
Minimal agent that runs in each virtual machine. It monitors for the file 'job.txt' to be created. Once this occurs, it parses the job metadata and executes the corresponding analysis script.

python/flux/flux.py
Central script for the flux plugin. Peforms initial setup actions for flux instrumentation library such as setting the app_init dll key. Starts and stops the named pipe server and pcap collection. Launches the browser to the target URL. Completes the job after the specified timeout. 

python/flux/pipeServer.py
Listens on a named pipe and forwards messages to the RabbitMQ server.

python/flux/fluxFilter.py
Filters messages as they flow through the named pipe server that match the rules file fluxFilter.txt

python/flux/fluxFilter.txt
Contains rules used to filter messages that match strings or regexes.

###Instrumentation Library
The Flux instrumentation library is responsible for being loaded into processes across the system. After load, it will hook key APIs in order to collect events such as file writes, process creation, registry writes, and exploit specific behavior. Each event is packed in MessagePack and forwarded to the named pipe server. Flux requires diStorm and msgpack-c which are available here:
https://github.com/gdabah/distorm
https://github.com/msgpack/msgpack-c

The following files are part of the instrumentation library:
flux/DllMain.cpp
flux/hook.cpp
flux/hook.h
flux/hook_file.cpp
flux/hook_inject.cpp
flux/hook_misc.cpp
flux/hook_network.cpp
flux/hook_process.cpp
flux/hook_registry.cpp
flux/log.cpp
flux/log.h
flux/MemGuard.cpp
flux/MemGuard.h
flux/ntapi.h
flux/whitelist.cpp
flux/whitelist.h



