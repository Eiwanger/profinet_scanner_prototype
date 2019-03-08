// @author Stefan Eiwanger


// main.c : Defines the entry point for the console application.
// get a list of adapters -> get user input for adapter, layer and if necessary ip address
// start listeners and send packets
// get user input for path to store the data
// free the data
// end



#include "stdafx.h"




// identification number of ip protocol
unsigned short identnmb = 0;

int main(int argc, char **argv) {

	// check if on windows, if so then load the npcap library
#ifdef WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls()) {
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	// allocate memory for temporary storage for device data and the data the functions need
	threadData_t* threadData = createDataStruct();

	// Pointer to the Exitcode of a thread
	LPDWORD lpExitCode = NULL;
	// obtain devicelist and print it
	int inum = 0;

	// get the list of possible devices
	if (obtainDeviceList(threadData) != 0)
	{
		printf_s("Error at obtainDeviceList\n");
		return -1;
	}

	// get interfacenumber to scan and send
	printf_s("Enter the interface number (1-%d):", threadData->numberOfAdapters);
	scanf_s("%d", &inum);
	getchar(); // flush buffer



	if (inum < 1 || inum > threadData->numberOfAdapters)
	{
		printf_s("\nInterface number out of range.\n");

		pcap_freealldevs(threadData->alldevs);
		free(threadData);
		return -1;
	}


	netAdapterNmb = inum;
	setOwnAddress(threadData);
	//---------------------------------------------------------------------------------------------------------------------


	// get mac addres of def gateway
	getAdapterDefaultGateway_MAC(threadData, getAdapterDefaultGateway_IP(threadData));




	printf("\nScan local (0) or remote (1): \n");
	scanf_s("%d", &inum);
	getchar(); // flush buffer


	if (inum == 1)
	{
		// insert target ip address   
		printf_s("\nTarget IP address form xxx.xxx.xxx.xxx-xxx: \n");
		char targetIP[4 * 3 + 3 + 1 + 1 + 3]; // 4*3 numbers, 3 dots and 1 \0
		targetIP[0] = 0;	// first init to zero


		fgets(targetIP, sizeof(targetIP), stdin);
		int range;
		if ((range = checkIP(targetIP, threadData)) == -1){
			pcap_freealldevs(threadData->alldevs);
			free(threadData);
			system("pause");
			return -1; // false IP
		}

		int l = 0;
		int dCounter = threadData->devCount;

		// we have all necessary information, start the scanning

		HANDLE sniffThreadrem = CreateThread(NULL, 0, sniffer_thread_remote, threadData, 0, lpExitCode);

		printf_s("\nSend RPC lookup endpointmapper first call \n");
		for (l = 0; l <= range; l++)
		{
			threadData->numberOfIPDev = l;
			sendPacket_RPC_rem(threadData, true);

		}

		WaitForSingleObject(sniffThreadrem, INFINITE);


		int defcount = linkedlist_status(threadData->first);
		if (defcount == -1)
		{
			printf_s("No devices found with given ip\n\n");
			pcap_freealldevs(threadData->alldevs);
			free(threadData);
			system("pause");
			return -1;
		}
		printf_s("\nRPC lookup first call finished \n\n");
		printf_s("\nSend RPC lookup endpointmapper second call \n");
		sniffThreadrem = CreateThread(NULL, 0, sniffer_thread_remote, threadData, 0, lpExitCode);



		for (int k = 0; k < defcount; k++){
			threadData->numberOfIPDev = k;
			sendPacket_RPC_rem(threadData, false);
		}
		WaitForSingleObject(sniffThreadrem, INFINITE);


		printf_s("\nRPC lookup second call finished \n\n");

		printf_s("\nSend RPC implicit read PDRealData \n");
		sniffThreadrem = CreateThread(NULL, 0, sniffer_thread_remote, threadData, 0, lpExitCode);

		for (int k = 0; k < defcount; k++){
			threadData->numberOfIPDev = k;

			sendpacket_IM_rem(threadData, PDREALDATA, NULL, 3);
		}
		WaitForSingleObject(sniffThreadrem, INFINITE);


		printf_s("\nPDRealData call finished \n\n");

		printf_s("\nSend RPC implicit read realidentificationdata \n");
		sniffThreadrem = CreateThread(NULL, 0, sniffer_thread_remote, threadData, 0, lpExitCode);
		for (int k = 0; k < defcount; k++){
			threadData->numberOfIPDev = k;

			sendpacket_IM_rem(threadData, REALIDENTIFICATIONDATA, NULL, 3);  // get all slots of the device
		}
		WaitForSingleObject(sniffThreadrem, INFINITE);

		printf_s("\nRealIdentificationData call finished \n\n");


		// send a request for each slot and subslot to get the data out of them
		sniffThreadrem = CreateThread(NULL, 0, sniffer_thread_remote, threadData, 0, lpExitCode);
		linked_list_t* list = threadData->first;
		slotParameter slotpara;
		printf_s("\nSend RPC implicit read PDRealData for one subslot \n");

		for (int k = 0; k < defcount; k++, list = list->next){
			linkedList_slot* slot = list->device->slotList;
			threadData->numberOfIPDev = k;

			slotpara.posSlot = 0;
			while (slot){
				linkedList_subslot* subslot = slot->subslotList;
				slotpara.posSubslot = 0;
				while (subslot){
					sendpacket_IM_rem(threadData, PDREALDATASUBMODUL, &slotpara, 3);  // get the data of each submodul
					Sleep(200); // ddos if the request are to fast, try slowing it down
					subslot = subslot->next;
					slotpara.posSubslot++;
				}
				slot = slot->next;
				slotpara.posSlot++;
			}

		}
		WaitForSingleObject(sniffThreadrem, INFINITE);
		printf_s("\nPDRealData for each subslot call finished \n\n");

		printf_s("\nSend RPC implicit read I&M data for each module \n");
		slotpara.posSubslot = -1; // set to non reachable value
		sniffThreadrem = CreateThread(NULL, 0, sniffer_thread_remote, threadData, 0, lpExitCode);
		list = threadData->first;
		for (int k = 0; k < defcount; k++, list = list->next){
			threadData->numberOfIPDev = k;

			linkedList_slot* slot = list->device->slotList;
			slotpara.posSlot = 0;
			while (slot){
				sendpacket_IM_rem(threadData, IM0, &slotpara, 3);  // get all slots of the device
				Sleep(200); // ddos if the request are to fast, try slowing it down
				slot = slot->next;
				slotpara.posSlot++;

			}
		}
		WaitForSingleObject(sniffThreadrem, INFINITE);

		printf_s("\nI&M data call for each module finished \n\n");

	}
	else
	{

		HANDLE sniffThread = CreateThread(NULL, 0, sniffer_thread_DCP, threadData, 0, lpExitCode);


		printf_s("\nSend pn_dcp \n");
		sendPacket_DCP(threadData);

		WaitForSingleObject(sniffThread, INFINITE);
		// every time a packet is recieved the timer of pcap_next_ex is restored to TIMEOUT seconds, if the TIMEOUT seconds are over the function returns 0
		printf_s("\npn_dcp finished\n\n");
		// so far so good it works

		sniffThread = CreateThread(NULL, 0, sniffer_thread_IP, threadData, 0, lpExitCode);

		// open new thread for sniffing of rcp packets
		int deviceCount = linkedlist_status(threadData->first);
		if (deviceCount == -1)
		{
			printf_s("List empty; no profinet devices in the subnet!");
			free(threadData->alldevs);
			free(threadData);
			return -1;
		}

		// for each device in the linkedlist send a rpc call
		printf_s("\nSend RPC lookup endpointmapper first call\n");

		for (int k = 0; k < deviceCount; k++){
			threadData->numberOfIPDev = k;
			sendPacket_RPC(threadData);
		}

		WaitForSingleObject(sniffThread, INFINITE);

		printf_s("\nRPC lookup first call finished \n\n");

		// again sniff against IP-RPC
		// this time the intern break should stop the loop
		printf_s("\nSend RPC lookup endpointmapper second call \n");
		sniffThread = CreateThread(NULL, 0, sniffer_thread_IP, threadData, 0, lpExitCode);
		for (int k = 0; k < deviceCount; k++){
			threadData->numberOfIPDev = k;
			sendPacket_RPC(threadData);
		}
		WaitForSingleObject(sniffThread, INFINITE);
		printf_s("\nRPC lookup second call finished \n\n");


		// reuse remote handler
		printf_s("\nSend RPC implicit read realidentificationdata \n");
		sniffThread = CreateThread(NULL, 0, sniffer_thread_remote, threadData, 0, lpExitCode);
		for (int k = 0; k < deviceCount; k++){

			threadData->numberOfIPDev = k;
			sendpacket_IM_rem(threadData, REALIDENTIFICATIONDATA, NULL, 2);  // get all slots of the device
		}
		WaitForSingleObject(sniffThread, INFINITE);


		// send a request for each slot and subslot to get the data out of them
		sniffThread = CreateThread(NULL, 0, sniffer_thread_remote, threadData, 0, lpExitCode);
		linked_list_t* list = threadData->first;
		slotParameter slotpara;
		printf_s("\nSend RPC implicit read PDRealData for one subslot \n");

		for (int k = 0; k < deviceCount; k++, list = list->next){
			linkedList_slot* slot = list->device->slotList;
			threadData->numberOfIPDev = k;

			slotpara.posSlot = 0;
			while (slot){
				linkedList_subslot* subslot = slot->subslotList;
				slotpara.posSubslot = 0;
				while (subslot){
					sendpacket_IM_rem(threadData, PDREALDATASUBMODUL, &slotpara, 2);  // get the data of each submodul
					Sleep(200); // ddos if the request are to fast, try slowing it down
					subslot = subslot->next;
					slotpara.posSubslot++;
				}
				slot = slot->next;
				slotpara.posSlot++;
			}

		}
		WaitForSingleObject(sniffThread, INFINITE);
		printf_s("\nPDRealData for each subslot call finished \n\n");


		printf_s("\nSend RPC implicit read I&M data for each module \n");
		slotpara.posSubslot = -1; // set to non reachable value
		sniffThread = CreateThread(NULL, 0, sniffer_thread_remote, threadData, 0, lpExitCode);
		list = threadData->first;

		for (int k = 0; k < deviceCount; k++, list = list->next){
			threadData->numberOfIPDev = k;

			linkedList_slot* slot = list->device->slotList;
			slotpara.posSlot = 0;
			while (slot){
				sendpacket_IM_rem(threadData, IM0, &slotpara, 2);  // get all slots of the device
				Sleep(200); // ddos if the request are to fast, try slowing it down
				slot = slot->next;
				slotpara.posSlot++;
			}
		}
		WaitForSingleObject(sniffThread, INFINITE);

		printf_s("\nI&M data call for each module finished \n\n");


	}



	// free list of devices
	pcap_freealldevs(threadData->alldevs);



	// write the list of devices to a xml file
	printf_s("\n\nWrite to file started\n\n");
	linked_list_t* tmp = threadData->first;
	char buff[MAX_FILENAME_LENGTH];
	printf("Please insert path/filename max %d characters, ending .xml\n", MAX_FILENAME_LENGTH);
	fgets(buff, sizeof(buff), stdin);

	stripEnter(buff, "\n");


	while (tmp != NULL)
	{
		writeToFile(tmp->device, buff, threadData->defaultGatewayMAC);
		tmp = tmp->next;
	}
	printf_s("Write to file finished\n\n");
	system("pause");

	empty_list(threadData->first);

	return 0;
}





/*-----------------------------------------------------------------------------------------*/
// function to load the Npcap library
#ifdef WIN32
BOOL LoadNpcapDlls() {
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

/*-----------------------------------------------------------------------------------------*/
// threadfuncitons for multithreading -> sniffing pn_packets (layer2)
DWORD WINAPI sniffer_thread_DCP(LPVOID lpParameter)
{
	captureDCPPackets(lpParameter);
	return 0;
}

/*-----------------------------------------------------------------------------------------*/

// threadfuncitons for multithreading -> sniffing IP packets (layer3)
DWORD WINAPI sniffer_thread_IP(LPVOID lpParameter)
{
	captureIPPackets(lpParameter);
	return 0;
}

/*-----------------------------------------------------------------------------------------*/

