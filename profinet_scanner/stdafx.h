// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdbool.h>
#include <time.h>




// TODO: reference additional headers your program requires here
#include "pcap.h"
#include "protocols.h"
#include "threading.h"

#include "linkedList.h"
#include "packetHandler.h"
#include "deviceHandler.h"
#include "filehandler.h"

#include "remoteScan.h"

#include <Iphlpapi.h>
#include <Assert.h>
#pragma comment(lib, "iphlpapi.lib")


#include <WS2tcpip.h>
#include <WinSock2.h>
#pragma comment(lib, "Ws2_32.lib")

#include <WinBase.h>
#include <processthreadsapi.h>


