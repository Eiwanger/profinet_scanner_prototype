#include <pcap.h>

extern time_t globalT;
extern clock_t t1_G;
extern pcap_t *adhandle;


extern int sendPacket_RPC_rem(threadData_t* threadData, bool firstCall);
extern int sendpacket_IM_rem(threadData_t* threadData, u_short parameterIndex, slotParameter* slotparameter);


extern void packet_handler_IP_rem(u_char* param, const struct pcap_pkthdr *header, const u_char *pkt_data);
extern int captureIPPackets_rem(threadData_t* threadData);

extern int checkIP(char* targetIP, threadData_t* threadData);

DWORD WINAPI sniffer_thread_remote(LPVOID lpParameter);

