# Technology Add On (TA) for the IMAP Mailbox app

This TA is meant to be installed on Universal Forwarders, indexers, or other Forwarders if you are running a distributed Splunk design.


## Install

1. Install this TA on all Forwarder(s) or Indexer(s) in the SPLUNK/etc/apps/ directory.
2. Install the App on your Search head(s).
 - Disable the input script.
 - Make sure that "disabled = true" for all of the inputs in the App under default/inputs.conf. 
3. Enable inputs on ONE of your TAs.
 - Pick just one of the TA installs to be the collection point.
 - Copy defaults/imap.conf to local/imap.conf
 - Edit local/imap.conf with your correct server and user settings.
 - Copy defaults/inputs.conf to local/inputs.conf
 - Edit the inputs.conf file and enable the Unix or Windows script input.
 - Set "disabled=false" to the script input to enable.
 - Restart splunk.


Note: Make sure that only ONE of the IMAP apps has the input script enabled. You will get email duplications if more than one is running.
