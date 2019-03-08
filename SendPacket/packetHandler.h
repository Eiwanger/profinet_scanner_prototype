//#include "stdafx.h"
#include <pcap.h>

#ifndef PACKETHANDLER_H
#define PACKETHANDLER_H


#define MAX_FILENAME_LENGTH 128
#define TIMEOUT1 1000
#define TIMEOUT2 2000
#define TIMEOUT4 4000
#define TIMEOUT  8000

int netAdapterNmb;
extern unsigned int seqNumberCounter;
extern unsigned short identnmb;

extern datasheet* createDatasheet();

extern void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

extern int captureAndInterpretPacket(threadData_t* threadData);
extern int sendPacket_DCP(threadData_t* threadData);
extern int sendPacket_RPC(threadData_t* threadData);
extern int sendpacket_IM(threadData_t* threadData, int deviceNumber, u_short index, slotParameter* slotpara);
//extern int sendpacket_IM(threadData_t* threadData, int deviceNumber);


extern bool compareMacAddress(mac_address file, mac_address packet);
extern bool checkDevicesFullExtracted(linked_list_t* deviceList);


extern void stripEnter(char *s, char* rem);
extern bool mystrcmp(char *s, char *d);

extern u_short combineTwoBytes(u_char highbyte, u_char lowbyte);


extern unsigned short calculateIPChecksum(u_char packet[]);
extern u_short BytesTo16(unsigned char X, unsigned char Y);
extern unsigned short calculateUDPChecksum(udp_pseudo_header udp_pHeader, u_char* packet_ip);
extern char* cutDataFromString(u_char *annotation, int* offset, bool lastItem);


extern int captureDCPPackets(threadData_t* threadData);
extern int captureIPPackets(threadData_t* threadData);
extern void packet_handler_dcp(u_char* param, const struct pcap_pkthdr *header, const u_char *pkt_data);
extern void packet_handler_IP(u_char* param, const struct pcap_pkthdr *header, const u_char *pkt_data);
extern void packet_handler_ImplicitRead(threadData_t* threadData, const struct pcap_pkthdr *header, const u_char * pkt_data);


extern bool timeDiff(long msDiff);


extern char* cutHardwareRevision(char* versions);
extern char* cutSoftVersion(char* versions);
extern char* removeDuplicate(char str[], int n);


//extern void getRealidentificationData(threadData_t* threadData, pn_ReadImplicit* pn_readimplicit, linked_list_t* currentDev);
extern void getRealidentificationData(pn_ReadImplicit* pn_readimplicit, linked_list_t* currentDev);


//extern void getPDRealData(threadData_t* threadData, pn_ReadImplicit* pn_readimplicit, linked_list_t* currentDev);
extern void getPDRealData(pn_ReadImplicit* pn_readimplicit, linked_list_t* currentDev);

//extern void getSubmodulPDRealData(threadData_t* threadData, pn_ReadImplicit* pn_readimplicit, mac_address mac);
extern void getSubmodulPDRealData(pn_ReadImplicit* pn_readimplicit, linked_list_t* currentDev);

extern void getIMData(pn_ReadImplicit* pn_readimplicit, linked_list_t* currentDev);


extern bool compareIPaddr(ip_address file, ip_address device);


#endif