========================================================================
    CONSOLE APPLICATION : SendPacket Project Overview
========================================================================



This program can send a profinet dcp call in the local subnet (layer 2) and listens for the answers
or scan a range of ip addresses from layer 3. 
If no answers were recieved, the program will end.
Else for every answer the listener catches a new RPC Endpointer mapper request will be sent and also catched again.
The RPC listener also uses a timeout to stop after a set time.
The layer 3 call uses more calls to get detailed information about the 
After this the data will be written to a new xml file. It is not possible at the current state to write in a existing file without overwriting.


The used protocolls are Profinet dcp (layer 2) and IP/UDP/RPC (layer 3)




/////////////////////////////////////////////////////////////////////////////

TODO 
- add error enum 
- change functions to return an error type instead of int or void
- change packet_handlerIP/packet_handlerIP_rem only difference is the way of comparing the data in the linkedlist with the data in the current packet


