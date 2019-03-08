#include "stdafx.h"
#include "packetHandler.h"
#include "deviceHandler.h"

pcap_t *adhandle;
time_t globalT;
clock_t t1_G;



/* Callback function invoked by libpcap for every incoming packet only for dcp packets*/
void packet_handler_dcp(u_char* param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm ltime;
	char timestr[16];
	ethernet_header *ethh;
	profinet_prot *profinet;
	datasheet* recData = NULL;
	threadData_t* threadData = (threadData_t*)param;

	time_t local_tv_sec;

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);



	// retrieve ethernet header
	ethh = (ethernet_header*)(pkt_data);



	// protocoll DCP
	profinet = (profinet_prot *)(pkt_data + 14); //length of ethernet header

	if (profinet == NULL){
		//	exit = true;
		return; // couldn't extract data
	}
	// 0x05 == Identify   0x01 == Response success
	if (profinet->serviceId != 0x05 || profinet->serviceType != 0x01){
		return; // not the response we are looking for
	}



	// Option 1byte suboption 1 byte blockinfo 2 byte dcpblocklength 2 byte
	int bl_count = 0;
	pn_data *pn_block;
	u_char* vendorValue;


	recData = createDatasheet();
	while (bl_count < ntohs(profinet->dataLength)){
		pn_block = (pn_data*)(pkt_data + 14 + 12 + bl_count);// 14 ethernet header, 12 rpc header + blocklength of used blocks
		pn_block->blocklength = ntohs(pn_block->blocklength);
		pn_block->blocklength += pn_block->blocklength % 2;

		switch (pn_block->option)
		{
		case OPT_IPOption:
			switch (pn_block->suboption)
			{
			case SUBOPT_IPO_MACAddress:
				break;
			case SUBOPT_IPO_IPParameter:;

				ip_address *src_IP = ((ip_address*)(pkt_data + 14 + 12 + bl_count + 6));
				recData->deviceIp.byte1 = src_IP->byte1;
				recData->deviceIp.byte2 = src_IP->byte2;
				recData->deviceIp.byte3 = src_IP->byte3;
				recData->deviceIp.byte4 = src_IP->byte4;

				ip_address *subnetmask = ((ip_address*)(pkt_data + 14 + 12 + bl_count + 6 + 4));
				recData->subnetmask.byte1 = subnetmask->byte1;
				recData->subnetmask.byte2 = subnetmask->byte2;
				recData->subnetmask.byte3 = subnetmask->byte3;
				recData->subnetmask.byte4 = subnetmask->byte4;

				ip_address *defaultGateway = ((ip_address*)(pkt_data + 14 + 12 + bl_count + 6 + 4 + 4));
				recData->defaultGateway.byte1 = defaultGateway->byte1;
				recData->defaultGateway.byte2 = defaultGateway->byte2;
				recData->defaultGateway.byte3 = defaultGateway->byte3;
				recData->defaultGateway.byte4 = defaultGateway->byte4;

				break;
			case SUBOPT_IPO_FUllIPSuite:
				break;
			default:
				break;
			}
			break;
		case OPT_DevicePropertiesOption:
			switch (pn_block->suboption)
			{
			case SUBOPT_DPO_DeviceVendor:;
				recData->deviceVendor = (char*)malloc(sizeof(char)*(pn_block->blocklength - 2 + 1)); // -2 because of Blockinfo and +1 for termination '\0'
				if (!recData->deviceVendor)
				{
					printf("Error allocating memory for devicevendor\n");
					return;
				}
				int i;
				vendorValue = (u_char*)pn_block;
				vendorValue += 6;

				for (i = 0; i < pn_block->blocklength - 2; i++)
				{
					recData->deviceVendor[i] = (char)((*(vendorValue + i))); // go from byte after blockinfo till blocklength end
				}
				recData->deviceVendor[i] = '\0';
				break;
			case SUBOPT_DPO_NameOfStation:;
				recData->nameOfStation = (char*)malloc(sizeof(char)*(pn_block->blocklength - 2 + 1)); // -2 because of Blockinfo and +1 for termination '\0'
				if (!recData->nameOfStation)
				{
					printf("Error allocating memory for name of station\n");
					return;
				}
				int j;
				vendorValue = (u_char*)pn_block;
				vendorValue += 6;

				for (j = 0; j < pn_block->blocklength - 2; j++)
				{
					recData->nameOfStation[j] = (char)((*(vendorValue + j))); // go from byte after blockinfo till blocklength end
				}
				recData->nameOfStation[j] = '\0';
				break;
			case SUBOPT_DPO_DeviceID:
				vendorValue = (u_char*)pn_block;
				vendorValue += 6;
				recData->vendorId = BytesTo16((u_char)*(vendorValue), (u_char)*(vendorValue + 1));
				recData->deviceId = BytesTo16((u_char)*(vendorValue + 2), (u_char)*(vendorValue + 3));
				break;
			case SUBOPT_DPO_DeviceRole:
				vendorValue = (u_char*)pn_block;
				vendorValue += 6;
				recData->deviceRoleDetail = (u_char)*(vendorValue);
				break;
			case SUBOPT_DPO_DeviceOptions: // only lists all the options which would be possible for the device
				break;
			case SUBOPT_DPO_AliasName:
				break;
			case SUBOPT_DPO_DeviceInstance:
				break;
			case SUBOPT_DPO_OEMDeviceID:
				break;
			case SUBOPT_DPO_StandardGateway:
				break;
			default:
				break;
			}
			break;
		case OPT_DHCPOption:	// not needed, implemention open for further use?
			break;
		case OPT_ControlOption: // not needed
			break;
		case OPT_DeviceInitiativeOption: // not needed
			break;
		case OPT_AllSelectorOption: // not needed only for
			break;
		default: // reserved? 
			break;
		}
		bl_count += 4 + pn_block->blocklength; // 6 byte block header (1 option, 1 suboption, 2 length)

	}
	recData->version = "";
	recData->deviceType = "";
	recData->orderId = "";
	recData->hardwareRevison = "";



	// get mac address
	recData->deviceMACaddress.byte1 = ethh->src_addrK.byte1;
	recData->deviceMACaddress.byte2 = ethh->src_addrK.byte2;
	recData->deviceMACaddress.byte3 = ethh->src_addrK.byte3;
	recData->deviceMACaddress.byte4 = ethh->src_addrK.byte4;
	recData->deviceMACaddress.byte5 = ethh->src_addrK.byte5;
	recData->deviceMACaddress.byte6 = ethh->src_addrK.byte6;

	// get the pointer to work with the endlocation


	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	//print timestamp and length of the packet 
	printf("%s.%.6d len:%d  %02x:%02x:%02x:%02x:%02x:%02x\n", timestr, header->ts.tv_usec, header->len, 
		ethh->src_addrK.byte1, ethh->src_addrK.byte2, ethh->src_addrK.byte3, ethh->src_addrK.byte4, ethh->src_addrK.byte5, ethh->src_addrK.byte6);

	// check first, if it is NULL malloc the first box
	linked_list_t* tmp = threadData->first;
	int sizeLinkedList = linkedlist_status(tmp);

	if (tmp == NULL)
	{
		threadData->first = malloc(sizeof(linked_list_t));
		if (!threadData->first)
		{
			printf("Error allocating memory for linkedList\n");
			return;
		}

		threadData->first->index = 0;
		threadData->first->device = recData;
		threadData->first->next = NULL;
		threadData->first->sequenceNum.byte1 = 0x01;
		threadData->first->sequenceNum.byte2 = 0x00;
		threadData->first->sequenceNum.byte3 = 0x00;
		threadData->first->sequenceNum.byte4 = 0x00;
		seqNumberCounter++;
		threadData->first->sBootTime.byte1 = 0x00;
		threadData->first->sBootTime.byte2 = 0x00;
		threadData->first->sBootTime.byte3 = 0x00;
		threadData->first->sBootTime.byte4 = 0x00;

		initHandle(&threadData->first->rpc_handle);

	}
	else{


		while (tmp != NULL)
		{
			if (compareMacAddress(tmp->device->deviceMACaddress, recData->deviceMACaddress))
			{
				// now mac address should be here a second time so bail out
				return;
			}
			tmp = tmp->next;
		}

		// create new datasheet
		add_to_list(threadData->first, recData, NULL);

	}
	// update timer

	t1_G = clock();
}



void packet_handler_IP(u_char* param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	ethernet_header *ethh;

	datasheet* recData = NULL;
	threadData_t* threadData = (threadData_t*)param;


	DCE_RPC_EM_CALL *dcerpccall;

	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	// convert the timestamp to readable format
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);


	// retrieve ethernet header
	ethh = (ethernet_header*)(pkt_data);



	// protocoll ip
	// get the position of the ip header
	ih = (ip_header *)(pkt_data + 14); //length of ethernet header


	// get the position of the udp header
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *)((u_char*)ih + ip_len);

	// convert from network byte order to host byte order
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);

	dcerpccall = (DCE_RPC_EM_CALL*)((u_char*)uh + 8);

	// check if its a read implicit call
	if (ntohs(dcerpccall->operationNumber) == 0x0005)
	{
		//packet_handler_ImplicitRead(threadData, header, pkt_data);
	}

	if (!(sport == dport && sport == 34964))
	{
		// exit, this packet has no use for me
		return;
	}



	if (dcerpccall->packetType == 0x00){
		return; // its the request
	}

	if (dcerpccall->epm_response.numEntries.byte1 != 0x01 && dcerpccall->epm_response.numEntries.byte4 != 0x01)
	{
		return; // empty packet?
	}

	// create temporary space
	recData = createDatasheet();

	int offset = 0;
	recData->deviceType = cutDataFromString(dcerpccall->epm_response.entries.entryService.towerPointer.annotation, &offset);
	recData->orderId = cutDataFromString(dcerpccall->epm_response.entries.entryService.towerPointer.annotation, &offset);
	char* versions = cutDataFromString(dcerpccall->epm_response.entries.entryService.towerPointer.annotation, &offset);


	recData->hardwareRevison = cutHardwareRevision(versions);
	recData->udpPort = ntohs(dcerpccall->epm_response.entries.entryService.towerPointer.floor4_udp.udp_port);

	recData->version = cutSoftVersion(versions);



	// everybody has a mac address
	recData->deviceMACaddress.byte1 = ethh->src_addrK.byte1;
	recData->deviceMACaddress.byte2 = ethh->src_addrK.byte2;
	recData->deviceMACaddress.byte3 = ethh->src_addrK.byte3;
	recData->deviceMACaddress.byte4 = ethh->src_addrK.byte4;
	recData->deviceMACaddress.byte5 = ethh->src_addrK.byte5;
	recData->deviceMACaddress.byte6 = ethh->src_addrK.byte6;


	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	//print timestamp and length of the packet
	printf("%s.%.6d len:%d  %d.%d.%d.%d\n", timestr, header->ts.tv_usec, header->len, ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);

	// check first, if it is NULL malloc the first box
	linked_list_t* tmpList = threadData->first;



	int sizeLinkedList = linkedlist_status(tmpList);

	// check if the deviceType is Unkown
	// if so, store the handle
	if (mystrcmp(recData->deviceType, "Unknown")){
		// first answer, returns a handle which we need
		// therefore the node exists
		while (tmpList != NULL)
		{
			if (compareMacAddress(tmpList->device->deviceMACaddress, recData->deviceMACaddress))
			{
				tmpList->rpc_handle = dcerpccall->epm_response.handle;

				return; // get back to sending another packet
			}
			tmpList = tmpList->next;
		}
		//	return; // get back to sending another packet
	}

	tmpList = threadData->first;


	while (tmpList != NULL)
	{
		if (compareMacAddress(tmpList->device->deviceMACaddress, recData->deviceMACaddress))
		{
			tmpList->device->deviceType = recData->deviceType;
			tmpList->device->orderId = recData->orderId;
			tmpList->device->version = recData->version;
			tmpList->device->hardwareRevison = recData->hardwareRevison;
			tmpList->device->udpPort = recData->udpPort;
			// added
			tmpList->rpc_handle = dcerpccall->epm_response.handle;
			// not important
			tmpList->finished = true;

			if (checkDevicesFullExtracted(threadData->first))
			{
				pcap_breakloop(adhandle);
			}
			t1_G = clock();
			return;
		}
		tmpList = tmpList->next;
	}
}


void packet_handler_ImplicitRead(threadData_t* threadData, const struct pcap_pkthdr *header, const u_char * pkt_data){
	ip_header *ih;
	udp_header *uh;
	ethernet_header *ethh;
	u_int ip_len;
	DCE_RPC_IM_CALL *dcerpccall;


	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;
	// convert the timestamp to readable format
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);


	ethh = (ethernet_header*)(pkt_data);

	// get mac address of sender to compare it later
	mac_address devMAC;
	devMAC.byte1 = ethh->src_addrK.byte1;
	devMAC.byte2 = ethh->src_addrK.byte2;
	devMAC.byte3 = ethh->src_addrK.byte3;
	devMAC.byte4 = ethh->src_addrK.byte4;
	devMAC.byte5 = ethh->src_addrK.byte5;
	devMAC.byte6 = ethh->src_addrK.byte6;


	// retireve the position of the ip header
	ih = (ip_header *)(pkt_data + 14); //length of ethernet header

	

	// retrieve the position of the udp header
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *)((u_char*)ih + ip_len);

	// get postition of the RPC call
	dcerpccall = (DCE_RPC_IM_CALL*)((u_char*)uh + 8);

	if (dcerpccall->packetType == 0x00)
		return; // request

	linked_list_t* currentDevice = threadData->first;
	while (currentDevice != NULL)
	{
		if (compareIPaddr(currentDevice->device->deviceIp, ih->saddr))
			break;
		else
			currentDevice = currentDevice->next;
	}

	if (currentDevice == NULL)
	{
		printf("Error Implicit Read answer for device which is not in list IP: %d.%d.%d.%d\n", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
		return;
	}

	// get address of the last byte of the rpc packet which is serialLow and add 1
	// check if this is necessary
	pn_ReadImplicit * pn_readimplicit = (pn_ReadImplicit*)(((u_char*)(&(dcerpccall->serialLow))) + 1);
	// get length of rpc fragment
	int lengthOfPN_Read = dcerpccall->fragmentLen;


	/* convert the timestamp to readable format */
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	//print timestamp and length of the packet
	printf("%s.%.6d len:%d  %d.%d.%d.%d\n", timestr, header->ts.tv_usec, header->len, ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);

	if (pn_readimplicit->errorDecode == 0x80) // error decode PNIORW
		return;	

	switch (ntohs(pn_readimplicit->index)){
	case IM0FILTERDATA: // of no use

		break;
	case PDREALDATA:	//is too big for a scalance with 24 ports, so reading not possible, but the interface data can be read
		// look at the sending of single packets for a device

		getPDRealData(pn_readimplicit, currentDevice);

		break;
	case REALIDENTIFICATIONDATA: 
		getRealidentificationData(pn_readimplicit, currentDevice);

		break;
	case IM0:;	// data is mostly already extracted
	
		break;
	case IM1:	// most of the time without value

		break;
	case IM2:	// most of the time without value

		break;
	case IM3:	// most of the time without value

		break;
	case PDREALDATASUBMODUL: // data from one submodul
		getSubmodulPDRealData(pn_readimplicit, currentDevice);
		break;
	default:	// unknown index
		break;
	}

}



int captureDCPPackets(threadData_t* threadData){
	pcap_if_t *d;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ether proto 0x8892";

	struct bpf_program fcode;

	LPDWORD lpExitCode = NULL;


	// Jump to the selected adapter 
	for (d = threadData->alldevs, i = 0; i < netAdapterNmb - 1; d = d->next, i++);

	// Open the adapter 
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,		// portion of the packet to capture. 
		1, //PCAP_OPENFLAG_PROMISCUOUS,			// promiscuous mode
		1000,		// read timeout
		errbuf		// error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
		return -1;
	}


	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		return -1;
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		return -1;
	}

	printf_s("\nlistening on %s for pn_dcp...\n", d->description);


	/* Retrieve the packets */

	/* start the capture */
	// the second parameter is a packet count, if it is reached, loop will be terminated/ 0 or -1 equals infinity
	t1_G = clock();
	HANDLE loopBreakThread = CreateThread(NULL, 0, loopTimerThread, NULL, 0, lpExitCode);
	if (loopBreakThread == NULL)
	{
		printf("Error loopBreakThread is NULL");
		return -1;
	}
	
	pcap_loop(adhandle, 0, packet_handler_dcp, (u_char*)threadData);

	WaitForSingleObject(loopBreakThread, INFINITE);

	pcap_close(adhandle);
	return 0;
}



int captureIPPackets(threadData_t* threadData){
	pcap_if_t *d;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ether proto 0x0800 and ip proto 0x11";

	struct bpf_program fcode;
	LPDWORD lpExitCode = NULL;


	// Jump to the selected adapter 
	for (d = threadData->alldevs, i = 0; i < netAdapterNmb - 1; d = d->next, i++);

	// Open the adapter 
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,		// portion of the packet to capture. 
		1, //PCAP_OPENFLAG_PROMISCUOUS,			// promiscuous mode
		1000,		// read timeout
		errbuf		// error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
		return -1;
	}


	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		return -1;
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		return -1;
	}

	printf_s("\nlistening on %s for IP/RPC...\n", d->description);


	/* start the capture */
	// the second parameter is a packet count, if it is reached, loop will be terminated 0 or -1 equals infinity
	t1_G = clock();
	HANDLE loopBreakThread = CreateThread(NULL, 0, loopTimerThread, NULL, 0, lpExitCode);
	
	if (loopBreakThread == NULL)
	{
		printf("Error loopBreakThread is NULL");
		return -1;
	}
	
	pcap_loop(adhandle, 0, packet_handler_IP, (u_char*)threadData);

	WaitForSingleObject(loopBreakThread, INFINITE);

	pcap_close(adhandle);
	return 0;
}



bool timeDiff(long msDiff){
	clock_t t2;
	//t1_G = clock();


	t2 = clock();

	float diff = ((float)(t2 - t1_G) / CLOCKS_PER_SEC) * 1000;
	if (diff > msDiff)
	{
		return true;
	}
	t1_G = t2;
	return false;
}


//  check every timeout if the time was set back if not, every packet should be here
DWORD WINAPI loopTimerThread(LPVOID lpParameter)
{
	while (true)
	{
		if (timeDiff(TIMEOUT4))
		{
			pcap_breakloop(adhandle);
			return 0;
		}
		else{
			Sleep(TIMEOUT10);
		}
	}
	return 0;
}


char* cutHardwareRevision(char* versions)
{
	int size = 0;
	int i = 0;
	char* pos = versions;
	if (!pos)
		return "";


	// first count till V
	while (*pos != 'V')
	{
		size++;
		pos = pos + 1;
	}
	// allocate memory with size
	char* hardwareRevision = malloc(sizeof(char)*(size + 1));

	if (!hardwareRevision)
	{
		printf("Error allocating memory for hardwareRevision");
		return NULL;
	}

	// copy the string
	for (i = 0; i < size; i++)
	{
		if (versions[i] == 0x20)
			break;

		hardwareRevision[i] = versions[i];
	}
	// add the termination
	hardwareRevision[i] = '\0';
	return hardwareRevision;
}


// extract the software version from the recieved answer
char* cutSoftVersion(char* versions)
{
	int i = 0;
	int size;
	char* pos = versions;
	char* softVersion;
	// coun till V
	while (*pos != 'V')
	{
		i++;
		pos = pos + 1;
	}

	//count whole string
	size = strlen(pos);
	softVersion = malloc(sizeof(char)* (size+1));
	if (!softVersion)
	{
		printf("Error allocating memory for softVersion");
		return NULL;
	}
	for (i = 0; i < size; i++)
	{
		softVersion[i] = pos[i];
	}
	softVersion[i] = '\0';

	softVersion = removeDuplicate(softVersion, size);
	return softVersion;
}


// remove duplicate spaces in the software version,
// @para str is a version string "V   1  20   1"
// @para int n is the size of the string
char *removeDuplicate(char str[], int n)
{
	// Used as index in the modified string 
	int i;

	// count till first occurence of a char other than 0x20
	for (i = 1; str[i] == 0x20; i++);

	// Traverse through all characters and put dots into whitespaces
	for (i; i < n; i++){
		if (str[i] == 0x20)
			str[i] = 0x2E; // .
	}
	char* p = str;
	i = 0;
	while (str[i] != '\0')
	{
		if (str[i] == str[i + 1] && (str[i] == 0x2E || str[i] == 0x20))
		{
			
			for (int j = i; j < n; j++){
				str[j] = str[j + 1];
			}
		}
		else
		{
			i++;
		}
	}
	str[i] = '\0';

	return str;
}

// extract parts from the annotation string
char* cutDataFromString(u_char *annotation, int* offset)
{
	char *destination = (char*)malloc(sizeof(char) * 32);
	if (!destination)
	{
		printf_s("Error allocating memory for string\n");
		return "";
	}
	int i = *offset;

	// count till spaces are not there anymore
	for (i; annotation[i] == 0x20; i++);

	// go from there till there are lots of spaces again
	for (int j = 0; j < 32; j++, i++)
	{
		if (annotation[i] == 0x20 && annotation[i + 1] == 0x20 && annotation[i + 2] == 0x20){
			*offset = i;
			destination = realloc(destination, sizeof(char)*(j));
			destination[j] = '\0';
			return destination; // end of important string; 
		}
		destination[j] = (char)annotation[i];
	}
	*offset = i;
	return destination;
}







// extract the slots and subslots from the answer to realIdentificationData
void getRealidentificationData(pn_ReadImplicit* pn_readimplicit, linked_list_t* currentDev){

	realIdentificationData* rID = (realIdentificationData*)(((u_char*)(&(pn_readimplicit->nextPos))));
	linked_list_t* list = currentDev;

	SubSlot* subp = NULL;


	int numberofslots = ntohs(rID->numberOfSlots);
	currentDev->device->numberOfSlots = numberofslots;
	if (numberofslots == 0) // mp slots to read
		return;


	Slot_P* slotp = (Slot_P*)(((u_char*)(&(rID->nextPos))));



	int counterSlots = 0;

	// create first slot
	if ((list->device->slotList = createSlotList()) == NULL)
	{
		printf_s("Error allocating memory for slotList");
		return;
	}

	linkedList_slot* currentSlot = list->device->slotList;

	// there is at least one slot
	do{
		// get slot data
		currentSlot->slotNumber = ntohs(slotp->slotNumber);
		currentSlot->numberOfSubmodules = ntohs(slotp->numberOfSubmodules);
		for (int n = 0; n < 4; n++)
			currentSlot->moduleIdentNumber[n] = slotp->moduleIdentNumber[n];

		// get subslotdata
		if (currentSlot->numberOfSubmodules == 0) // no subslots to read
			return;
		
		// create first subslot
		if ((currentSlot->subslotList = createSubslotList()) == NULL)
		{
			printf_s("Error allocating memory for subslotlist");
			return;
		}
		linkedList_subslot* currentSubSlot = currentSlot->subslotList;

		int counterSubslots = 0;
		int nmbOfSm = currentSlot->numberOfSubmodules;
		subp = (SubSlot*)(((u_char*)(&(slotp->nextPos))));
		do{
			currentSubSlot->subslotNumber = ntohs(subp->subslotNumber);
			for (int n = 0; n < 4; n++)
				currentSubSlot->submoduleIdentNumber[n] = subp->submoduleIdentNumber[n];

			counterSubslots++;
			if (counterSubslots < nmbOfSm){
				currentSubSlot->next = createSubslotList();
				currentSubSlot = currentSubSlot->next;
				subp = (SubSlot*)(((u_char*)(&(subp->submoduleIdentNumber[3]))) + 1);
			}

			
		} while (counterSubslots < nmbOfSm);

		counterSlots++;
		if (counterSlots < numberofslots){
			currentSlot->next = createSlotList();
			currentSlot = currentSlot->next;
			slotp = (Slot_P*)(((u_char*)(&(subp->submoduleIdentNumber[3]))) + 1);

		}

	} while (counterSlots < numberofslots);

	// now we should have all the slots and subslots of the device
}


// extract data from the PDRealdata call, especially mac address, subnetmask, default gateway
void getPDRealData(pn_ReadImplicit* pn_readimplicit, linked_list_t* currentDev)
{
	multipleBlockHeader* mBH = (multipleBlockHeader*)((&(pn_readimplicit->nextPos)));

	u_char* startPD = (u_char*)mBH;

	//linked_list_t* list = currentDev;

	if (ntohs(pn_readimplicit->blockheader.blocktype) != 0x8009)
		return;

	
	


	// next blockheader 1 byte after last byte of mBH
	Blockheader* bh = (Blockheader*)(((u_char*)(&(mBH->subslotnumber))) + 2);
	int recordDatalength = 0;
	for (int i = 0; i < 4; i++)
	{
		recordDatalength = recordDatalength << 8; // shouldn't do anything in the first round, because length is 0
		recordDatalength += pn_readimplicit->recordDataLength[i];

	}



	while ((((u_char*)bh) - startPD) < recordDatalength)
	{
		int multBlockLength = ntohs(mBH->blockheader.blocklength);
		u_char* startmBH = (u_char*)(&bh->blockVersionHigh);

		
			do{
			if (ntohs(bh->blocktype) == PDINTERFACEDATAREAL)
			{
				u_char* ownChassisLength = (((u_char*)(&(bh->blockVersionLow))) + 1); // pos after the blockversion
				currentDev->device->nameOfStation = malloc(sizeof(char)* ((*ownChassisLength) + 1));
				if (currentDev->device->nameOfStation == NULL)
				{
					printf("Error allocating memory for nameofstation\n");
					return;
				}
				int n;



				for (n = 0; n < *ownChassisLength; n++)
				{
					currentDev->device->nameOfStation[n] = ownChassisLength[1 + n]; // after length the chassis id follows
				}
				currentDev->device->nameOfStation[n] = '\0';

			// after name of station the only in special cases there is a padding


				// TODO fix error
				u_char * position = &ownChassisLength[n + 1];
				if ((*ownChassisLength + 23) % 4 != 0)
				{
					double tmp = (*ownChassisLength + 23) % 4;
					tmp = tmp / 4;

					position += (int)((1-tmp)*4);
				}

				/*if (ownChassisLength[1 + n ] == 0x00 && ownChassisLength[ 2 +n] == 0x00) // there is propably a padding
					position = &ownChassisLength[n + 3]; // start of mac address
				else
					position = &ownChassisLength[n + 1];
				*/
				// mac address is needed
				currentDev->device->deviceMACaddress.byte1 = *position;
				currentDev->device->deviceMACaddress.byte2 = *(position + 1);
				currentDev->device->deviceMACaddress.byte3 = *(position + 2);
				currentDev->device->deviceMACaddress.byte4 = *(position + 3);
				currentDev->device->deviceMACaddress.byte5 = *(position + 4);
				currentDev->device->deviceMACaddress.byte6 = *(position + 5);

				position = position + 6; 
				// after mac address there is always a padding of 2 bytes

			//	if (position[0] == 0x00 && position[1] == 0x00) // again padding
					position =	&position[2];

				position = position + 4; // ip address is not needed

				// start of subnetmask
				currentDev->device->subnetmask.byte1 = *position;
				currentDev->device->subnetmask.byte2 = *(position + 1);
				currentDev->device->subnetmask.byte3 = *(position + 2);
				currentDev->device->subnetmask.byte4 = *(position + 3);

				position = position + 4; // start of default gateway

				currentDev->device->defaultGateway.byte1 = *position;
				currentDev->device->defaultGateway.byte2 = *(position + 1);
				currentDev->device->defaultGateway.byte3 = *(position + 2);
				currentDev->device->defaultGateway.byte4 = *(position + 3);


				// we have now everything we need -> end funciton
				return;
			}
			else{
				bh = (Blockheader*)(((u_char*)(&bh->blockVersionHigh)) + ntohs(bh->blocklength)); // jump to the next blockheader
			}
			} while ((((u_char*)bh) - startmBH) < multBlockLength);
			

		// jump to the next multiple blockheader
		mBH =(multipleBlockHeader*) ((u_char*)mBH) + ntohs(mBH->blockheader.blocklength);

	}



}


// extract the data from one subslot e.g. peers
void getSubmodulPDRealData(pn_ReadImplicit* pn_readimplicit, linked_list_t* currentDev)
{
	linked_list_t* list = currentDev;

	pdPortData* pdPD = (pdPortData*)(((u_char*)(&(pn_readimplicit->padding_end[19]))) + 1);

	u_short slotnumber = ntohs(pdPD->slotnumber);
	u_short subslotnumber = ntohs(pdPD->subslotnumber);


	if (pn_readimplicit->errorCode != 0x00 || pn_readimplicit->errorCode1 != 0x00 || pn_readimplicit->errorCode2 != 0x00 || pn_readimplicit->errorDecode != 0x00)
		return;


	linkedList_slot* slot = list->device->slotList;
	
	// go to the right slot
	bool end = false;
	while (!end)
	{
		if (slot->slotNumber == slotnumber)
			end = true;
		else
			slot = slot->next;
	}

	// got to the right subslot
	end = false;
	linkedList_subslot* subslots = slot->subslotList;

	while (!end)
	{
		if (subslots->subslotNumber == subslotnumber)
			end = true;
		else
			subslots = subslots->next;
	}

	// right device, right slot, right subslot

	// may extract information like mautype mediatype etc
	if (pdPD->numberOfPeers == 0)
	{
		pdPortDataWithoutPeer* pdpdwp = (pdPortDataWithoutPeer*)&pdPD->pos;
	
	}
	else // we have at least one peer
	{
		pdPortDataWithPeer* pdpdWithP = (pdPortDataWithPeer*)&pdPD->pos;
		
		// set pointer to start of chassis id
		u_char* peerChassisID_p = &pdpdWithP->lengthPeerChassisID + 1;

		if((subslots->peerChassisID = malloc(sizeof(char)* (pdpdWithP->lengthPeerChassisID+1)))==NULL)
			return;
		
		int i;
		for (i = 0; i < pdpdWithP->lengthPeerChassisID; i++)
		{
			subslots->peerChassisID[i] = *(peerChassisID_p + i);
		}
		subslots->peerChassisID[i] = '\0';

		// padding 3 byte, linedelay 4 byte

		peerChassisID_p += i - 2 + 3 + 4;

		// now we should have the position of the mac address;
		subslots->peerMacAddress = malloc(sizeof(mac_address));
		if (!subslots->peerMacAddress)
		{
			printf("Error allocating memory for peerMacAddress\n");
			return;
		}

		subslots->peerMacAddress->byte1 = ((mac_address*)peerChassisID_p)->byte1;
		subslots->peerMacAddress->byte2 = ((mac_address*)peerChassisID_p)->byte2;
		subslots->peerMacAddress->byte3 = ((mac_address*)peerChassisID_p)->byte3;
		subslots->peerMacAddress->byte4 = ((mac_address*)peerChassisID_p)->byte4;
		subslots->peerMacAddress->byte5 = ((mac_address*)peerChassisID_p)->byte5;
		subslots->peerMacAddress->byte6 = ((mac_address*)peerChassisID_p)->byte6;

	}

	t1_G = clock();
	return;
}














