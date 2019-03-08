// @author Stefan Eiwanger


// main.c : Defines the entry point for the console application.

#include "stdafx.h"








int main(int argc, char **argv) {

#ifdef WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls()) {
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	// allocate memory for temporary storage for device data and the data the functions need
	threadData_t* threadData = createDataStruct();


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
			printf_s("No devices found with given ip");
			pcap_freealldevs(threadData->alldevs);
			free(threadData);
			system("pause");
			return -1;
		}

		printf_s("\nSend RPC lookup endpointmapper second call \n");
		sniffThreadrem = CreateThread(NULL, 0, sniffer_thread_remote, threadData, 0, lpExitCode);



		for (int k = 0; k < defcount; k++){
			threadData->numberOfIPDev = k;
			sendPacket_RPC_rem(threadData, false);
		}
		WaitForSingleObject(sniffThreadrem, INFINITE);



		printf_s("\nSend RPC implicit read PDRealData \n");
		sniffThreadrem = CreateThread(NULL, 0, sniffer_thread_remote, threadData, 0, lpExitCode);

		for (int k = 0; k < defcount; k++){
			threadData->numberOfIPDev = k;

			sendpacket_IM_rem(threadData, PDREALDATA, NULL);
		}
		WaitForSingleObject(sniffThreadrem, INFINITE);



		printf_s("\nSend RPC implicit read realidentificationdata \n");
		sniffThreadrem = CreateThread(NULL, 0, sniffer_thread_remote, threadData, 0, lpExitCode);
		for (int k = 0; k < defcount; k++){
			threadData->numberOfIPDev = k;

			sendpacket_IM_rem(threadData, REALIDENTIFICATIONDATA, NULL);  // get all slots of the device
		}
		WaitForSingleObject(sniffThreadrem, INFINITE);




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
					sendpacket_IM_rem(threadData, PDREALDATASUBMODUL, &slotpara);  // get the data of each submodul
					subslot = subslot->next;
					slotpara.posSubslot++;
				}
				slot = slot->next;
				slotpara.posSlot++;
			}

		}
		WaitForSingleObject(sniffThreadrem, INFINITE);
	}
	else
	{

		HANDLE sniffThread = CreateThread(NULL, 0, sniffer_thread_DCP, threadData, 0, lpExitCode);

		if (sniffThread == NULL)
		{
			// if not exit
			ExitProcess(3);
		}
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
		printf_s("\nSend RPC lookup endpointmapper \n");

		for (int k = 0; k < deviceCount; k++){
			sendPacket_RPC(threadData, k);
		}

		WaitForSingleObject(sniffThread, INFINITE);

		printf_s("\nrpc1 finished\n\n");

		// again sniff against IP-RPC
		//  this time the intern break should stop the loop
		printf_s("\nSend RPC lookup endpointmapper second call \n");
		sniffThread = CreateThread(NULL, 0, sniffer_thread_IP, threadData, 0, lpExitCode);
		for (int k = 0; k < deviceCount; k++){
			sendPacket_RPC(threadData, k);
		}
		WaitForSingleObject(sniffThread, INFINITE);
		printf_s("\nrpc2 finished\n\n");


		// write the list of devices to a file

	}
	// free list of devices
	pcap_freealldevs(threadData->alldevs);

	printf_s("\n\nWrite to file started\n\n");
	linked_list_t* tmp = threadData->first;
	char buff[MAX_FILENAME_LENGTH];
	printf("Please insert path/filename max %d characters, ending .xml\n", MAX_FILENAME_LENGTH);
	fgets(buff, sizeof(buff), stdin);

	stripEnter(buff, "\n");


	while (tmp != NULL)
	{
		writeToFile(tmp->device, buff);
		tmp = tmp->next;
	}
	printf_s("Write to file finished\n\n");
	system("pause");

	empty_list(threadData->first);

	return 0;
}





/*-----------------------------------------------------------------------------------------*/

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

DWORD WINAPI sniffer_thread_DCP(LPVOID lpParameter)
{
	captureDCPPackets(lpParameter);
	return 0;
}

/*-----------------------------------------------------------------------------------------*/

DWORD WINAPI sniffer_thread_IP(LPVOID lpParameter)
{
	captureIPPackets(lpParameter);
	return 0;
}

/*-----------------------------------------------------------------------------------------*/

