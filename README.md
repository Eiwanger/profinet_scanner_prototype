The scanner itself contains a own README where a description to the functionalities and future improvements are stated. It was programed on Visual Studio Express.

This program was a test for what is possible to scan in a system with profinet devices. It was created during an internship at the BMW Group.

It uses the NPCAP library to send packets over a ethernet connection to the devices and listens for theirs answers to parse them. I've made it in a console application that works only on windows because I used the windows libraries for multithreading. The used protocols are profinet DCP, ethernet, ip, udp and dce rpc.

If you want to use the program, look on https://nmap.org/npcap/ for the licence. Also go there if you don't understand how the sending and receiving works. They got a documentation for that. I used the Npcap SDK 1.01 (ZIP) from https://nmap.org/npcap/

I made a lot of comments to the program. For me it was a way to understand the different protocols and how they work. Maybe it also helps others.
