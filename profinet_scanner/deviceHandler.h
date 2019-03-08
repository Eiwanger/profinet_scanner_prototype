
#include "stdafx.h"
#include <pcap.h>


#define IPTOSBUFFERS    12

extern void ifprint(pcap_if_t *d, int count);
extern int obtainDeviceList(threadData_t* threadData);
extern char *iptos(u_long in);
extern char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
extern void extractIP(ip_address* ip, u_long address);
extern void getIP_SUB(pcap_if_t *d, threadData_t* threadData);
extern void setOwnAddress(threadData_t* threadData);
extern mac_address* getMAC(const char *ip);

extern ip_address* getAdapterDefaultGateway_IP(threadData_t* threadData);
extern void getAdapterDefaultGateway_MAC(threadData_t* threadData, ip_address* defaultGateway);


extern threadData_t* createDataStruct();