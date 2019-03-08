

#include "stdafx.h"
#include "deviceHandler.h"
#include <pcap.h>

int obtainDeviceList(threadData_t* threadData)
{
	pcap_if_t *alldevs = NULL;
	pcap_if_t *d;
	int adaperCount = 0;
	char errbuf[PCAP_ERRBUF_SIZE];


	/* Retrieve the device list from the local machine */
	if (pcap_findalldevs(&alldevs, errbuf) == -1) 
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d != NULL; d = d->next)
	{
		// Scan the list printing every entry


		printf("%d. %s", ++(adaperCount), d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");

	}


	/*
	// print additional infos to the found adapters
	int count = 0;
	for (d = alldevs; d; d = d->next)
	{
	(count)++;
	ifprint(d, count);
	}
	*/


	if ((adaperCount) == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");

		// wait to see if it worked

		return -1;
	}
	if (!alldevs)
	{
		// list was empty
		// bail out
		printf_s("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}

	threadData->numberOfAdapters = adaperCount;
	threadData->alldevs = alldevs;

	return 0;
}

/*-----------------------------------------------------------------------------------------*/
// print one device with extra information
void ifprint(pcap_if_t *d, int count)
{
	pcap_addr_t *a;
	char ip6str[128];

	/* Name */
	printf("Adapternummer: %d\n", count);
	printf("%s\n", d->name);

	/* Description */
	if (d->description)
		printf("\tDescription: %s\n", d->description);



	/* Loopback Address*/
	printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

	/* IP addresses */
	for (a = d->addresses; a; a = a->next) {
		printf("\tAddress Family: #%d\n", a->addr->sa_family);
		// 23 if ipv6 || 2 if ipv4
		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (a->addr)
				printf("\tAddress: %s\n", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
			if (a->netmask)
				printf("\tNetmask: %s\n", iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
			if (a->broadaddr)
				printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
			if (a->dstaddr)
				printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
			break;

		case AF_INET6:
			printf("\tAddress Family Name: AF_INET6\n");
			if (a->addr)
				printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
			break;

		default:
			printf("\tAddress Family Name: Unknown\n");
			break;
		}
	}
	printf("\n\n");
}
/*-----------------------------------------------------------------------------------------*/

/* From tcptraceroute, convert a numeric IP address to a string */
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	_snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

/*-----------------------------------------------------------------------------------------*/
// convert ipv6 to string
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
	socklen_t sockaddrlen;

#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif

	if (getnameinfo(sockaddr,
		sockaddrlen,
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}


// get the own address of MAC and IP
void setOwnAddress(threadData_t* threadData)
{
	pcap_if_t *d;
	int i;
	for (d = threadData->alldevs, i = 0; i < netAdapterNmb - 1; d = d->next, i++);

	getIP_SUB(d, threadData);

	char ip[15];
	//char dot = '.';

	sprintf_s(ip, sizeof(char) * 15, "%d.%d.%d.%d", threadData->ownIp.byte1, threadData->ownIp.byte2, threadData->ownIp.byte3, threadData->ownIp.byte4);

	mac_address* m_address = getMAC(ip);
	threadData->ownMac.byte1 = m_address->byte1;
	threadData->ownMac.byte2 = m_address->byte2;
	threadData->ownMac.byte3 = m_address->byte3;
	threadData->ownMac.byte4 = m_address->byte4;
	threadData->ownMac.byte5 = m_address->byte5;
	threadData->ownMac.byte6 = m_address->byte6;

}

// extract the ip address and subnetmask from a given device
void getIP_SUB(pcap_if_t *d, threadData_t* threadData)
{
	pcap_addr_t *a;

	/* IP addresses */
	for (a = d->addresses; a; a = a->next) {
		//ipv4 equals 2, we only need ipv4
		switch (a->addr->sa_family)
		{
		case AF_INET:
			if (a->addr)
				extractIP(&threadData->ownIp, ((struct sockaddr_in *)a->addr)->sin_addr.s_addr);
			if (a->netmask)
				extractIP(&threadData->subnetmask, ((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);
			break;
		default:
			break;
		}
	}
	printf("\n\n");
}

// convert the long ip address to a struct ip address
void extractIP(ip_address* ip, u_long address)
{
	u_char* p = (u_char *)&address;
	ip->byte1 = *p;
	ip->byte2 = *(p + 1);
	ip->byte3 = *(p + 2);
	ip->byte4 = *(p + 3);
}




/**
* @return the mac address of the interface with the given ip
*/
mac_address* getMAC(const char *ip){
	PIP_ADAPTER_INFO AdapterInfo;
	DWORD dwBufLen = sizeof(AdapterInfo);
	char *mac_addr = (char*)malloc(17);
	mac_address* macad;
	if ((macad = malloc(sizeof(mac_address))) == NULL){
		printf("Error allocating memory needed to store mac address\n");
		return NULL;
	}

	AdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (AdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return NULL;
	}

	// Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen variable
	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(AdapterInfo);
		AdapterInfo = (IP_ADAPTER_INFO *)malloc(dwBufLen);
		if (AdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return NULL;
		}
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;// Contains pointer to current adapter info
		do {
			macad->byte1 = pAdapterInfo->Address[0];
			macad->byte2 = pAdapterInfo->Address[1];
			macad->byte3 = pAdapterInfo->Address[2];
			macad->byte4 = pAdapterInfo->Address[3];
			macad->byte5 = pAdapterInfo->Address[4];
			macad->byte6 = pAdapterInfo->Address[5];

			char* tmp = pAdapterInfo->IpAddressList.IpAddress.String;

			if (strcmp(ip, pAdapterInfo->IpAddressList.IpAddress.String) == 0){
				free(AdapterInfo);
				return macad;
			}
			printf("\n");
			pAdapterInfo = pAdapterInfo->Next;
		} while (pAdapterInfo);
	}
	free(AdapterInfo);
	return NULL;
}

// fuction returns the default gateway (ip) of a lokal interface with help of the mac address
ip_address* getAdapterDefaultGateway_IP(threadData_t* threadData)
{
	ULONG outBufLen = 15000;
	ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST;
	ULONG family = AF_INET;

	DWORD dwRetVal = 0;
	PIP_ADAPTER_ADDRESSES pAddresses = NULL;


	do{
		if ((pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen)) == NULL)
		{
			printf("Error allocating memory for AdaperAdresses");
			return NULL;
		}

		dwRetVal = GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);

		if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
			free(pAddresses);
			pAddresses = NULL;
			outBufLen += 5000;
		}
		else{
			break;
		}

	} while (1);

	bool end = false;
	while (pAddresses->Next != NULL && !end)
	{
		mac_address local;
		local.byte1 = pAddresses->PhysicalAddress[0];
		local.byte2 = pAddresses->PhysicalAddress[1];
		local.byte3 = pAddresses->PhysicalAddress[2];
		local.byte4 = pAddresses->PhysicalAddress[3];
		local.byte5 = pAddresses->PhysicalAddress[4];
		local.byte6 = pAddresses->PhysicalAddress[5];

		if (compareMacAddress(local, threadData->ownMac)){
			ip_address* def_gateway = malloc(sizeof(ip_address));
			if (!def_gateway)
				return NULL;

			int i;
			if (!pAddresses->FirstGatewayAddress){
				printf("Error no default Gateway address for this adapter\n");
				return NULL;

			}
			for (i = 0; pAddresses->FirstGatewayAddress->Address.lpSockaddr->sa_data[i] == 0; i++);
			u_char* dg = (((u_char*)pAddresses->FirstGatewayAddress->Address.lpSockaddr->sa_data)+i);
			def_gateway->byte1 = *dg;
			def_gateway->byte2 = *(dg + 1);
			def_gateway->byte3 = *(dg + 2);
			def_gateway->byte4 = *(dg + 3);


			//free(pAddresses);
			return def_gateway;


		}
		else{
			pAddresses = pAddresses->Next;
		}

	}


	return NULL;
}

#define BUFSIZE 256
// send a ping to the given ip and read the arp table with the cmd 
void getAdapterDefaultGateway_MAC(threadData_t* threadData, ip_address* defaultGateway)
{
	// ping the default gateway
	// use arp -a ipaddress to get the mac address of router

	// size of ping buffer 
	char pingbuf[32];
	sprintf_s(pingbuf, sizeof(pingbuf), "ping -n 1 -l 1 %d.%d.%d.%d", defaultGateway->byte1, defaultGateway->byte2, defaultGateway->byte3, defaultGateway->byte4 );

	char arpbuf[32];
	sprintf_s(arpbuf, sizeof(arpbuf), "arp -a %d.%d.%d.%d", defaultGateway->byte1, defaultGateway->byte2, defaultGateway->byte3, defaultGateway->byte4);

	// build string to compare
	char ipaddr[16];
	sprintf_s(ipaddr, sizeof(ipaddr), "%d.%d.%d.%d", defaultGateway->byte1, defaultGateway->byte2, defaultGateway->byte3, defaultGateway->byte4);
	

	char outbuf[BUFSIZE];
	FILE* fp;

	// ping the default gateway to make sure it is in the arp table
	if ((fp = _popen(pingbuf, "r")) == NULL)
	{
		printf("Error opening pipe!\n");
		return;
	}
	if (_pclose(fp))  {
		printf("Command not found or exited with error status\n");
		return;

	}


	if ((fp = _popen(arpbuf, "r")) == NULL)
	{
		printf("Error opening pipe!\n");
		return;
	}

	while (fgets(outbuf, BUFSIZE, fp) != NULL) {}

	// arp stops at the given ip, it shows only the given ip
	int offset = 0;
	
	char * foundIPaddr = cutDataFromString((u_char*)outbuf, &offset);
	char * mac = cutDataFromString((u_char*)outbuf, &offset); // string with form xx-xx-xx-xx-xx-xx to xxxxxxxxxxxx

	stripEnter(mac, "-");

	if ((threadData->defaultGatewayMAC = malloc(sizeof(mac_address))) == NULL)
	{
		printf("Error allocating memory for defaultGatewayMac address");
		return;
	}

	char buff[5]= { '0', 'x', ' ', ' ', '\0'};
	u_char mac_u[6];
	for (int i = 0, j = 0; i < 6; i++, j=j+2)
	{

		buff[2] = mac[j];
		buff[3] = mac[j + 1];
		//buff[4] = 0;
		mac_u[i] =(u_char) strtol(buff, NULL, 0);
	}
	
	

	if (_pclose(fp))  {
		printf("Command not found or exited with error status\n");
		return;
	
	}
	
	threadData->defaultGatewayMAC->byte1 = mac_u[0];
	threadData->defaultGatewayMAC->byte2 = mac_u[1];
	threadData->defaultGatewayMAC->byte3 = mac_u[2];
	threadData->defaultGatewayMAC->byte4 = mac_u[3];
	threadData->defaultGatewayMAC->byte5 = mac_u[4];
	threadData->defaultGatewayMAC->byte6 = mac_u[5];


}


threadData_t* createDataStruct()
{
	threadData_t* tD = malloc(sizeof(threadData_t));
	if (!tD)
	{
		printf("Error allocating memory for data struct");
		return NULL;
	}

	tD->first = NULL;
	tD->targetIP = NULL;
	tD->defaultGatewayMAC = NULL;
	tD->devCount = 0;

	return tD;
}