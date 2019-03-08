#include "stdafx.h"
#include "packetHandler.h"
#include "deviceHandler.h"

//##############################################################################################################################################################


rpc_activity* activityIM = NULL;




int sendPacket_DCP(threadData_t* threadData)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet_dcp[DCP_PACKETSIZE];
	pcap_if_t *d;

	// build the packet

	// set mac destination address
	// DCP identify multicast address
	packet_dcp[0] = 0x01;
	packet_dcp[1] = 0x0E;
	packet_dcp[2] = 0xCF;
	packet_dcp[3] = 0x00;
	packet_dcp[4] = 0x00;
	packet_dcp[5] = 0x00;


	// set mac source address
	packet_dcp[6] = threadData->ownMac.byte1;
	packet_dcp[7] = threadData->ownMac.byte2;
	packet_dcp[8] = threadData->ownMac.byte3;
	packet_dcp[9] = threadData->ownMac.byte4;
	packet_dcp[10] = threadData->ownMac.byte5;
	packet_dcp[11] = threadData->ownMac.byte6;


	// Typfeld
	packet_dcp[12] = 0x88; // 8892 == DCP
	packet_dcp[13] = 0x92;


	// Nutzdaten  here starts the profinet realtime protocoll
	// doku at pn-al-protocoll_2722 at 95

	// FrameID
	packet_dcp[14] = 0xfe; // identify request 0xfefe
	packet_dcp[15] = 0xfe;

	// ServiceID
	packet_dcp[16] = 0x05;	// 0x  01 == Get   02 == set   05 == identify

	// ServiceType
	packet_dcp[17] = 0x00;

	// Xid
	packet_dcp[18] = 0x01; // This field shall be coded as data type Unsigned32. 
	packet_dcp[19] = 0x00; // It shall contain a transaction identification chosen 
	packet_dcp[20] = 0x00; // by the client to associate requests and responses between a client and a server.
	packet_dcp[21] = 0x01;


	// Response Delay
	packet_dcp[22] = 0x00; // be careful
	packet_dcp[23] = 0x05; // look into calculation

	// Dcp Datalength
	packet_dcp[24] = 0x00;
	packet_dcp[25] = 0x04;

	// start block
	// Option
	packet_dcp[26] = OPT_AllSelectorOption;  // 0xff == all options
	// suboption
	packet_dcp[27] = SUBOPT_ASO_AllSelector;  // 0xff == all suboptions

	// Dcp Blocklength
	packet_dcp[28] = 0x00;
	packet_dcp[29] = 0x00;


	/* Fill the rest of the packet */
	int i; // variable for counting
	for (i = 30; i < DCP_PACKETSIZE; i++) {
		packet_dcp[i] = (u_char)0;
	}

	// Jump to the selected adapter 
	for (d = threadData->alldevs, i = 0; i < netAdapterNmb - 1; d = d->next, i++);

	//getIP_SUB(d, threadData);

	/* Open the adapter */
	if ((fp = pcap_open_live(d->name,		// name of the device
		65536,// portion of the packet to capture. It doesn't matter in this case
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
		)) == NULL) {
		fprintf(stderr,
			"\nUnable to open the adapter. %s is not supported by Npcap\n",
			(char*)d);
		return 2;
	}

	// send packet
	if (pcap_sendpacket(fp,	// Adapter
		packet_dcp,				// buffer with the packet
		DCP_PACKETSIZE					// size
		) != 0) {
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
		return 3;
	}
	pcap_close(fp);

	return 0;
}

/*-----------------------------------------------------------------------------------------*/



int sendPacket_RPC(threadData_t* threadData)
{
	pcap_t *fp;
	u_char packet_ip[IP_UDP_RPC_PACKETSIZE];

	char errbuf[PCAP_ERRBUF_SIZE];

	int i = 0;
	pcap_if_t *d;

	// own implemention
	// get the devicelist and jump to the ethernet adapter
	if (!threadData->alldevs)
	{
		// list was empty
		// bail out
		return -1;
	}

	// Jump to the selected adapter 
	for (d = threadData->alldevs, i = 0; i < netAdapterNmb - 1; d = d->next, i++);


	// Plan 2 
	// rpc remote process controll
	// eth -> IP -> UDP -> RPC -> ?

	//	IPHeader
	//	IP_VersionIHL(0x45), IP_DifferentiatedServices, IP_TotalLength, IP_Identification,
	//  IP_Flags_FragOffset a, IP_TTL, IP_Protocol, IP_HeaderChecksum, IP_SrcIPAddress, IP_DstIPAddress, [IP_Options] b
	//	The encoding of the fields shall be according to IETF RFC 791.

	//	UDPHeader
	//	UDP_SrcPort, UDP_DstPort, UDP_DataLength, UDP_Checksum c

	// RPCHeader S.272
	// RPCVersion (4), RPCPacketType, RPCFlags, RPCFlags2, RPCDRep, RPCSerialHigh, RPCObjectUUID a, 
	// RPCInterfaceUUID b, RPCActivityUUID, RPCServerBootTime, RPCInterfaceVersion,
	// RPCSequenceNmb, RPCOperationNmb c, RPCInterfaceHint, RPCActivityHint, RPCLengthOfBody,
	// RPCFragmentNmb, RPCAuthenticationProtocol, RPCSerialLow


	// Destination mac address
	// exact address of destination device
	// has to be variable
	// use struct for faster transfer?

	// jump to device destination in linked List
	linked_list_t* currentDevice = threadData->first;

	for (int i = 0; i < threadData->numberOfIPDev; i++, currentDevice = currentDevice->next);

	packet_ip[0] = currentDevice->device->deviceMACaddress.byte1;
	packet_ip[1] = currentDevice->device->deviceMACaddress.byte2;
	packet_ip[2] = currentDevice->device->deviceMACaddress.byte3;
	packet_ip[3] = currentDevice->device->deviceMACaddress.byte4;
	packet_ip[4] = currentDevice->device->deviceMACaddress.byte5;
	packet_ip[5] = currentDevice->device->deviceMACaddress.byte6;

	
	packet_ip[6] = threadData->ownMac.byte1;
	packet_ip[7] = threadData->ownMac.byte2;
	packet_ip[8] = threadData->ownMac.byte3;
	packet_ip[9] = threadData->ownMac.byte4;
	packet_ip[10] = threadData->ownMac.byte5;
	packet_ip[11] = threadData->ownMac.byte6;


	// Typefield 
	packet_ip[12] = 0x08;  // 0x0800 Internet Protocol RPC   
	packet_ip[13] = 0x00;



	// ip Header + data Length 20 bytes because 5*4 = 20 
	packet_ip[14] = 0x45;
	// Explicit Congestion Notification:
	packet_ip[15] = 0x00;  // not ECN-Capable Transport

	// total length ethernet needs 14 bytes IP_UDP_RPC_PACKETSIZE is defined with 198
	packet_ip[16] = 0x00;
	packet_ip[17] = 0xb8;

	// Identification
	packet_ip[18] = 0x00;
	packet_ip[19] = 0x0a;

	// Fragment offset
	packet_ip[20] = 0x00;
	packet_ip[21] = 0x00;

	// time to life
	packet_ip[22] = 0x40;

	// Protocoll
	packet_ip[23] = 0x11; // == UDP

	// Headerchecksum
	packet_ip[24] = 0x00; // set to 0 before calc
	packet_ip[25] = 0x00;

	// ip source in hexadecimal 

	packet_ip[26] = threadData->ownIp.byte1;
	packet_ip[27] = threadData->ownIp.byte2;
	packet_ip[28] = threadData->ownIp.byte3;
	packet_ip[29] = threadData->ownIp.byte4;

	// ip destination in hexadecimal
	// same read from struct

	packet_ip[30] = currentDevice->device->deviceIp.byte1;
	packet_ip[31] = currentDevice->device->deviceIp.byte2;
	packet_ip[32] = currentDevice->device->deviceIp.byte3;
	packet_ip[33] = currentDevice->device->deviceIp.byte4;

	// calculate the checksum and integrate the result into the header
	unsigned short checksum = calculateIPChecksum(packet_ip);
	packet_ip[24] = checksum & 0xFF;
	packet_ip[25] = checksum >> 8;


	// start of udp header
	// Source port
	packet_ip[34] = 0x88;		// NDREPMapLookupReq or NDREPMapLookupFreeReq 0x8894 
	packet_ip[35] = 0x94;		// 0x8892 UDP-RTC-PDU, UDP-RTA-PDU

	// destination port
	packet_ip[36] = 0x88;		// NDREPMapLookupReq or NDREPMapLookupFreeReq 0x8894 
	packet_ip[37] = 0x94;		// 0x8892 UDP-RTC-PDU, UDP-RTA-PDU

	// Length
	int udp_len = UDP_PACKETSIZE;

	packet_ip[38] = htons(udp_len) & 0xFF;
	packet_ip[39] = htons(udp_len) >> 8;

	// checksum of udp header set to 0 first
	packet_ip[40] = 0x00;
	packet_ip[41] = 0x00;



	// calculation of udp header
	udp_pseudo_header udp_pHeader;
/*	udp_pHeader.srcIp1 = packet_ip[26];
	udp_pHeader.srcIp2 = packet_ip[27];
	udp_pHeader.srcIp3 = packet_ip[28];
	udp_pHeader.srcIp4 = packet_ip[29];

	udp_pHeader.destIp1 = packet_ip[30];
	udp_pHeader.destIp2 = packet_ip[31];
	udp_pHeader.destIp3 = packet_ip[32];
	udp_pHeader.destIp4 = packet_ip[33];
*/
	udp_pHeader.protocoll = packet_ip[23];
	udp_pHeader.udp_length = udp_len;




	// version (start dce/rpc)  syntax at s. 273
	packet_ip[42] = 0x04;   // only 0x04 possible, everything else is reserved

	// packet type
	// 0x00 Request
	// 0x01 Ping
	// 0x02 Response
	// 0x03 Fault
	// 0x04 Working
	// 0x05 No call, response to ping
	// 0x06 Reject
	// 0x07 Acknowledge
	// 0x08 Connectionless cancel
	// 0x09 Fragment acknowledge (FACK-PDU)
	// 0x0A Cancel acknowledge
	// 0x0B - 0xFF reserved
	packet_ip[43] = 0x00;



	// reserved for implemention flag 1
	packet_ip[44] = 0x20;

	// reserved for implemention flag 2
	packet_ip[45] = 0x00;

	// till now more or less no need to change for different devices (mac address has to be changed)


	// data representation	 ? equals a placeholder
	packet_ip[46] = 0x10; // charakter  // 0x?0 == ascii   0x?1 == EBCDIC   0x0? == Big endian    0x1? == little endian
	packet_ip[47] = 0x00; // floating point // 0x00 == IEEE   0x01 == VAX   0x02 == CRAY   0x03 == IBM 0x04 - 0xFF == reserved
	packet_ip[48] = 0x00; // The value of the third octet shall be zero. src: S.275

	// serial high
	packet_ip[49] = 0x00; // This field shall be coded as data type Unsigned8. The value contains the high octet of the fragment number of the call.

	// objectUUID // wireshark doesn't display anything for these bytes  // doku at pn-al-protocol at 276
	packet_ip[50] = 0x00;
	packet_ip[51] = 0x00;
	packet_ip[52] = 0x00;
	packet_ip[53] = 0x00;
	packet_ip[54] = 0x00;
	packet_ip[55] = 0x00;
	packet_ip[56] = 0x00;
	packet_ip[57] = 0x00;
	packet_ip[58] = 0x00;
	packet_ip[59] = 0x00;
	packet_ip[60] = 0x00;
	packet_ip[61] = 0x00;
	packet_ip[62] = 0x00;
	packet_ip[63] = 0x00;
	packet_ip[64] = 0x00;
	packet_ip[65] = 0x00;

	// interfaceUUID for the end point mapper src 277 
	packet_ip[66] = 0x08;
	packet_ip[67] = 0x83;
	packet_ip[68] = 0xaf;
	packet_ip[69] = 0xe1; // UID_EPMap_Interface  E1AF8308-5D1F-11C9  --> little endian? 91a4-08002b14a0fa

	packet_ip[70] = 0x1f;
	packet_ip[71] = 0x5d;
	packet_ip[72] = 0xc9;
	packet_ip[73] = 0x11;

	packet_ip[74] = 0x91;	// big endian 
	packet_ip[75] = 0xa4;
	packet_ip[76] = 0x08;
	packet_ip[77] = 0x00;
	packet_ip[78] = 0x2b;
	packet_ip[79] = 0x14;
	packet_ip[80] = 0xa0;
	packet_ip[81] = 0xfa;

	// Activity
	packet_ip[82] = 0x01;  // lookup 
	packet_ip[83] = 0x00;  // docu says that the RPCActivityUUID will be generated for each AR
	packet_ip[84] = 0x00;
	packet_ip[85] = 0x00;
	packet_ip[86] = 0x01;
	packet_ip[87] = 0x00;
	packet_ip[88] = 0x01;
	packet_ip[89] = 0x00;
	packet_ip[90] = 0x01;
	packet_ip[91] = 0x00;
	packet_ip[92] = 0x00;
	packet_ip[93] = 0x01;
	packet_ip[94] = 0x00;
	packet_ip[95] = 0x01;
	packet_ip[96] = 0x00;
	packet_ip[97] = 0x01;

	// Server boot time  first packet has to be sent with all 0
	// plan to overwrite the 0 with the answer of the device

	packet_ip[98] = 0x00;
	packet_ip[99] = 0x00;
	packet_ip[100] = 0x00;
	packet_ip[101] = 0x00;

	// interface version
	packet_ip[102] = 0x03;
	packet_ip[103] = 0x00;
	packet_ip[104] = 0x00;
	packet_ip[105] = 0x00;

	// sequence num // for each request has to a unique number created 

	rpc_sequenceNum sqNum;
	createSeqNum(&sqNum);
	packet_ip[106] = sqNum.byte1;
	packet_ip[107] = sqNum.byte2;
	packet_ip[108] = sqNum.byte3;
	packet_ip[109] = sqNum.byte4;

	// Operation number opnum  // Opt == optional  // Man == Mandatory
	// PNIO services: 0  Connect  |  1  Release  |  2 Read  |  3 Write  |  4 Control  |  5 Read implicit  |  6 - 65535 Reserved  |  src: S. 278
	// endpoint mapper: 0  Opt insert | 1 Opt Delete | 2 Man Lookup | 3 Opt Map | 4 Man LookupHandleFree | 5 Opt InqObject | 6 Opt MgmtDelete | else reserved
	packet_ip[110] = 0x02;
	packet_ip[111] = 0x00;

	// interface hint
	packet_ip[112] = 0xff; // for this version should be set to 0xFFFF 
	packet_ip[113] = 0xff; // client starts with 0xFFFF and then uses the servers response

	// activity hint
	packet_ip[114] = 0xff; // for this version should be set to 0xFFFF 
	packet_ip[115] = 0xff; // client starts with 0xFFFF and then uses the servers response

	// fragment len length of body
	packet_ip[116] = 0x4c; // The value shall be set to the number of octets of NDRData of the current frame.
	packet_ip[117] = 0x00;

	// fragment num
	packet_ip[118] = 0x00; //The value shall be set to the number of the current fragment
	packet_ip[119] = 0x00;

	// auth proto
	packet_ip[120] = 0x00; // The value shall be set to zero for no authentication

	// serial low
	packet_ip[121] = 0x00; // This field shall be coded as data type Unsigned8. The value contains the low octet of the fragment number of the call.

	// dce/rpc endpoint mapper
	// inquiry type
	// rpc_c_ep_all_elts   (= src wireshark)
	// Returns every element from the endpoint map.
	//	The if_id, vers_option and object_uuid arguments are ignored. (src. https://pubs.opengroup.org/onlinepubs/9629399/rpc_mgmt_ep_elt_inq_begin.htm)
	packet_ip[122] = 0x00;
	packet_ip[123] = 0x00;
	packet_ip[124] = 0x00;
	packet_ip[125] = 0x00;


	// referece id // The value shall be set to 1 according to little or big endian.   src: S.282
	packet_ip[126] = 0x01;
	packet_ip[127] = 0x00;
	packet_ip[128] = 0x00;
	packet_ip[129] = 0x00;

	// object
	packet_ip[130] = 0x00;
	packet_ip[131] = 0x00;
	packet_ip[132] = 0x00;
	packet_ip[133] = 0x00;
	packet_ip[134] = 0x00;
	packet_ip[135] = 0x00;
	packet_ip[136] = 0x00;
	packet_ip[137] = 0x00;
	packet_ip[138] = 0x00;
	packet_ip[139] = 0x00;
	packet_ip[140] = 0x00;
	packet_ip[141] = 0x00;
	packet_ip[142] = 0x00;
	packet_ip[143] = 0x00;
	packet_ip[144] = 0x00;
	packet_ip[145] = 0x00;

	// Reference id // The value shall be set to 2 according to little or big endian.   src: S.282
	packet_ip[146] = 0x02;
	packet_ip[147] = 0x00;
	packet_ip[148] = 0x00;
	packet_ip[149] = 0x00;

	// interface
	packet_ip[150] = 0x01;		// DEA00001-6C97-11D1-8271-00A02442DF7D  src: S. 277 // Identifies the interface of an IO device uniquely.
	packet_ip[151] = 0x00;
	packet_ip[152] = 0xa0;
	packet_ip[153] = 0xde;

	packet_ip[154] = 0x97;
	packet_ip[155] = 0x6c;
	packet_ip[156] = 0xd1;
	packet_ip[157] = 0x11;
	packet_ip[158] = 0x82;
	packet_ip[159] = 0x71;
	packet_ip[160] = 0x00;
	packet_ip[161] = 0xa0;
	packet_ip[162] = 0x24;
	packet_ip[163] = 0x42;
	packet_ip[164] = 0xdf;
	packet_ip[165] = 0x7d;

	// version major
	packet_ip[166] = 0x01;
	packet_ip[167] = 0x00;

	// version minor
	packet_ip[168] = 0x00;
	packet_ip[169] = 0x00;

	// version option // The value shall be set to 1 according to little or big endian src: S.282
	packet_ip[170] = 0x01;
	packet_ip[171] = 0x00;
	packet_ip[172] = 0x00;
	packet_ip[173] = 0x00;

	// handle  first set 0 as long as handle is NULL


	packet_ip[174] = currentDevice->rpc_handle.byte1;
	packet_ip[175] = currentDevice->rpc_handle.byte2;
	packet_ip[176] = currentDevice->rpc_handle.byte3;
	packet_ip[177] = currentDevice->rpc_handle.byte4;
	packet_ip[178] = currentDevice->rpc_handle.byte5;
	packet_ip[179] = currentDevice->rpc_handle.byte6;
	packet_ip[180] = currentDevice->rpc_handle.byte7;
	packet_ip[181] = currentDevice->rpc_handle.byte8;
	packet_ip[182] = currentDevice->rpc_handle.byte9;
	packet_ip[183] = currentDevice->rpc_handle.byte10;
	packet_ip[184] = currentDevice->rpc_handle.byte11;
	packet_ip[185] = currentDevice->rpc_handle.byte12;
	packet_ip[186] = currentDevice->rpc_handle.byte13;
	packet_ip[187] = currentDevice->rpc_handle.byte14;
	packet_ip[188] = currentDevice->rpc_handle.byte15;
	packet_ip[189] = currentDevice->rpc_handle.byte16;
	packet_ip[190] = currentDevice->rpc_handle.byte17;
	packet_ip[191] = currentDevice->rpc_handle.byte18;
	packet_ip[192] = currentDevice->rpc_handle.byte19;
	packet_ip[193] = currentDevice->rpc_handle.byte20;

	// max entries  // The value shall be set at least to 1. src: S.283
	packet_ip[194] = 0x01;
	packet_ip[195] = 0x00;
	packet_ip[196] = 0x00;
	packet_ip[197] = 0x00;

	udp_pHeader.udp_data = malloc(sizeof(char)*UDP_PACKETSIZE);
	for (int i = 42; i < IP_UDP_RPC_PACKETSIZE; i++)
	{
		udp_pHeader.udp_data[i - 42] = packet_ip[i];
	}

	// update checksum
	checksum = calculateUDPChecksum(udp_pHeader, packet_ip);
	packet_ip[40] = checksum & 0xFF;
	packet_ip[41] = checksum >> 8;

	/* Open the adapter */
	//printf_s("Try to open adapter:\n");

	if ((fp = pcap_open_live(d->name,		// name of the device
		65536,// portion of the packet to capture. It doesn't matter in this case
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
		)) == NULL) {
		fprintf(stderr,
			"\nUnable to open the adapter. %s is not supported by Npcap\n",
			(char*)d);
		return 2;
	}

	//printf_s("Try to send packet:\n");

	if (pcap_sendpacket(fp,	// Adapter
		packet_ip,				// buffer with the packet
		IP_UDP_RPC_PACKETSIZE					// size
		) != 0) {
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
		return 3;
	}




	pcap_close(fp);
	return 0;

}

/*-----------------------------------------------------------------------------------------*/

/* PNIO-CM changes for different calls
	IODReadReqHeader

	I&M0FilterData
	Index [176] [177]     0xf840
	PDRealData
	Index [176] [177]	  0xf841
	RealIdentificationData for one api
	Index [176] [177]	  0xf000
	I&M0
	Index [176] [177]     0xaff0
	I&M1
	Index [176] [177]     0xaff1
	I&M2
	Index [176] [177]     0xaff2
	I&M3
	Index [176] [177]     0xaff3

	=> parameterIndex will be set at the callling function
*/

int sendpacket_IM(threadData_t* threadData, int deviceNumber, u_short parameterIndex, slotParameter* slotparameter)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];

	u_char packet_IM[IP_UDP_RPC_IM_PACKETSIZE];

	int i = 0;
	//	int inum;
	pcap_if_t *d;




	// implement the ethernet ip udp rpc header


	for (d = threadData->alldevs, i = 0; i < netAdapterNmb - 1; d = d->next, i++);



	// Plan 2 
	// rpc remote process controll
	// eth -> IP -> UDP -> RPC -> ?

	//	IPHeader
	//	IP_VersionIHL(0x45), IP_DifferentiatedServices, IP_TotalLength, IP_Identification,
	//  IP_Flags_FragOffset a, IP_TTL, IP_Protocol, IP_HeaderChecksum, IP_SrcIPAddress, IP_DstIPAddress, [IP_Options] b
	//	The encoding of the fields shall be according to IETF RFC 791.

	//	UDPHeader
	//	UDP_SrcPort, UDP_DstPort, UDP_DataLength, UDP_Checksum c

	// RPCHeader S.272
	// RPCVersion (4), RPCPacketType, RPCFlags, RPCFlags2, RPCDRep, RPCSerialHigh, RPCObjectUUID a, 
	// RPCInterfaceUUID b, RPCActivityUUID, RPCServerBootTime, RPCInterfaceVersion,
	// RPCSequenceNmb, RPCOperationNmb c, RPCInterfaceHint, RPCActivityHint, RPCLengthOfBody,
	// RPCFragmentNmb, RPCAuthenticationProtocol, RPCSerialLow


	// Destination mac address
	// jump to device destination in linked List
	linked_list_t* currentDevice = threadData->first;

	for (int i = 0; i < deviceNumber; i++, currentDevice = currentDevice->next);

	packet_IM[0] = currentDevice->device->deviceMACaddress.byte1;
	packet_IM[1] = currentDevice->device->deviceMACaddress.byte2;
	packet_IM[2] = currentDevice->device->deviceMACaddress.byte3;
	packet_IM[3] = currentDevice->device->deviceMACaddress.byte4;
	packet_IM[4] = currentDevice->device->deviceMACaddress.byte5;
	packet_IM[5] = currentDevice->device->deviceMACaddress.byte6;

// set  source mac address
	packet_IM[6] = threadData->ownMac.byte1;
	packet_IM[7] = threadData->ownMac.byte2;
	packet_IM[8] = threadData->ownMac.byte3;
	packet_IM[9] = threadData->ownMac.byte4;
	packet_IM[10] = threadData->ownMac.byte5;
	packet_IM[11] = threadData->ownMac.byte6;


	// Typefield 
	packet_IM[12] = 0x08;  // 0x0800 Internet Protocol RPC   
	packet_IM[13] = 0x00;



	// ip Header + data Length 20 bytes because 5*4 = 20 
	packet_IM[14] = 0x45;
	// Explicit Congestion Notification:
	packet_IM[15] = 0x00;  // not ECN-Capable Transport

	// total length ethernet needs 14 bytes IP_UDP_RPC_IM_PACKETSIZE is defined with 198
	packet_IM[16] = 0x00;
	packet_IM[17] = 0xc0;

	// Identification
//	packet_IM[18] = 0x00;
//	packet_IM[19] = 0x0a;

	// Identification
	packet_IM[18] = identnmb >> 8;
	//packet_IM[19] = 0x0a;
	packet_IM[19] = identnmb & 0xFF;
	identnmb++;

	// Fragment offset
	packet_IM[20] = 0x00;
	packet_IM[21] = 0x00;

	// time to life
	packet_IM[22] = 0x80;

	// Protocoll
	packet_IM[23] = 0x11; // == UDP

	// Headerchecksum
	packet_IM[24] = 0x00; // set to 0 before calc
	packet_IM[25] = 0x00;

	// ip source in hexadecimal
	packet_IM[26] = threadData->ownIp.byte1;
	packet_IM[27] = threadData->ownIp.byte2;
	packet_IM[28] = threadData->ownIp.byte3;
	packet_IM[29] = threadData->ownIp.byte4;

	// ip destination in hexadecimal
	// same read from struct

	packet_IM[30] = currentDevice->device->deviceIp.byte1;
	packet_IM[31] = currentDevice->device->deviceIp.byte2;
	packet_IM[32] = currentDevice->device->deviceIp.byte3;
	packet_IM[33] = currentDevice->device->deviceIp.byte4;

	// calculate the checksum and integrate the result into the header
	unsigned short checksum = calculateIPChecksum(packet_IM);
	packet_IM[24] = checksum & 0xFF;
	packet_IM[25] = checksum >> 8;


	// start of udp header
	// Source port
	packet_IM[34] = 0x88;		// NDREPMapLookupReq or NDREPMapLookupFreeReq 0x8894 
	packet_IM[35] = 0x94;		// 0x8892 UDP-RTC-PDU, UDP-RTA-PDU

	// destination port

	packet_IM[36] = currentDevice->device->udpPort >> 8;		// NDREPMapLookupReq or NDREPMapLookupFreeReq 0x8894 
	packet_IM[37] = currentDevice->device->udpPort & 0xff;		// 0x8892 UDP-RTC-PDU, UDP-RTA-PDU

	// Length
	u_short udp_len = UDP_IM_PACKETSIZE;

	packet_IM[38] = htons(udp_len) & 0xFF;
	packet_IM[39] = htons(udp_len) >> 8;

	// checksum of udp header set to 0 first
	packet_IM[40] = 0x00;
	packet_IM[41] = 0x00;



	// calculation of udp header
	udp_pseudo_header udp_pHeader;
/*	udp_pHeader.srcIp1 = packet_IM[26];
	udp_pHeader.srcIp2 = packet_IM[27];
	udp_pHeader.srcIp3 = packet_IM[28];
	udp_pHeader.srcIp4 = packet_IM[29];

	udp_pHeader.destIp1 = packet_IM[30];
	udp_pHeader.destIp2 = packet_IM[31];
	udp_pHeader.destIp3 = packet_IM[32];
	udp_pHeader.destIp4 = packet_IM[33];
*/
	udp_pHeader.protocoll = packet_IM[23];
	udp_pHeader.udp_length = udp_len;




	// version (start dce/rpc)  syntax at s. 273
	packet_IM[42] = 0x04;   // only 0x04 possible, everything else is reserved

	// packet type
	// 0x00 Request
	// 0x01 Ping
	// 0x02 Response
	// 0x03 Fault
	// 0x04 Working
	// 0x05 No call, response to ping
	// 0x06 Reject
	// 0x07 Acknowledge
	// 0x08 Connectionless cancel
	// 0x09 Fragment acknowledge (FACK-PDU)
	// 0x0A Cancel acknowledge
	// 0x0B - 0xFF reserved
	packet_IM[43] = 0x00;

	// reserved for implemention flag 1
	packet_IM[44] = 0x20;

	// reserved for implemention flag 2
	packet_IM[45] = 0x00;

	// till now more or less no need to change for different devices (mac address has to be changed)


	// data representation	 ? equals a placeholder
	packet_IM[46] = 0x10; // charakter  // 0x?0 == ascii   0x?1 == EBCDIC   0x0? == Big endian    0x1? == little endian
	packet_IM[47] = 0x00; // floating point // 0x00 == IEEE   0x01 == VAX   0x02 == CRAY   0x03 == IBM 0x04 - 0xFF == reserved
	packet_IM[48] = 0x00; // The value of the third octet shall be zero. src: S.275

	// serial high
	packet_IM[49] = 0x00; // This field shall be coded as data type Unsigned8. The value contains the high octet of the fragment number of the call.

	// objectUUID // doku at pn-al-protocol at 276
	packet_IM[50] = 0x00;
	packet_IM[51] = 0x00;
	packet_IM[52] = 0xA0;
	packet_IM[53] = 0xDE;
	packet_IM[54] = 0x97;
	packet_IM[55] = 0x6c;
	packet_IM[56] = 0xd1;
	packet_IM[57] = 0x11;
	packet_IM[58] = 0x82;
	packet_IM[59] = 0x71;
	// variable part
	packet_IM[60] = 0x00;
	packet_IM[61] = 0x01; 

	// device id 
	packet_IM[62] = currentDevice->device->deviceId >> 8;
	packet_IM[63] = currentDevice->device->deviceId & 0xFF;

	// vendor id
	currentDevice->device->vendorId;
	packet_IM[64] = currentDevice->device->vendorId >> 8;
	packet_IM[65] = currentDevice->device->vendorId & 0xFF;

	// interfaceUUID  now change for I&M
	packet_IM[66] = 0x01;
	packet_IM[67] = 0x00;
	packet_IM[68] = 0xa0;
	packet_IM[69] = 0xde; // PNIO (Device Interface)  dea00001-6c97-11d1-8271-00a02442df7d

	packet_IM[70] = 0x97;
	packet_IM[71] = 0x6c;
	packet_IM[72] = 0xd1;
	packet_IM[73] = 0x11;

	packet_IM[74] = 0x82;	
	packet_IM[75] = 0x71;

	packet_IM[76] = 0x00;
	packet_IM[77] = 0xa0;
	packet_IM[78] = 0x24;
	packet_IM[79] = 0x42;
	packet_IM[80] = 0xdf;
	packet_IM[81] = 0x7d;

	// Activity

	packet_IM[82] = 0x80;
	packet_IM[83] = 0xd2;  // docu says that the RPCActivityUUID will be generated for each AR -> lies
	packet_IM[84] = 0x2e;
	packet_IM[85] = 0xb6;
	packet_IM[86] = 0x55;
	packet_IM[87] = 0x1e;
	packet_IM[88] = 0xb2;
	packet_IM[89] = 0x11;
	packet_IM[90] = 0x01;
	packet_IM[91] = 0x00;
	packet_IM[92] = 0x08;
	packet_IM[93] = 0x00;
	packet_IM[94] = 0x06;
	packet_IM[95] = 0x73;
	packet_IM[96] = 0x68;
	packet_IM[97] = 0x28;

	// Server boot time  first packet has to be sent with all 0

	packet_IM[98] = 0x00;
	packet_IM[99] = 0x00;
	packet_IM[100] = 0x00;
	packet_IM[101] = 0x00;

	// interface version
	packet_IM[102] = 0x01; // copied from wireshark
	packet_IM[103] = 0x00;
	packet_IM[104] = 0x00;
	packet_IM[105] = 0x00;

	// sequence num // for each request has to be a unique number created 
	// the request has to be new use seqNum counter
	rpc_sequenceNum sqNum;
	createSeqNum(&sqNum);
	packet_IM[106] = sqNum.byte1;
	packet_IM[107] = sqNum.byte2;
	packet_IM[108] = sqNum.byte3;
	packet_IM[109] = sqNum.byte4;


	// Operation number opnum  // Opt == optional  // Man == Mandatory // for this call use PNIO
	// PNIO services: 0  Connect  |  1  Release  |  2 Read  |  3 Write  |  4 Control  |  5 Read implicit  |  6 - 65535 Reserved  |  src: S. 278
	// endpoint mapper: 0  Opt insert | 1 Opt Delete | 2 Man Lookup | 3 Opt Map | 4 Man LookupHandleFree | 5 Opt InqObject | 6 Opt MgmtDelete | else reserved
	packet_IM[110] = 0x05;
	packet_IM[111] = 0x00;

	// interface hint
	packet_IM[112] = 0xff; // for this version should be set to 0xFFFF 
	packet_IM[113] = 0xff; // client starts with 0xFFFF and then uses the servers response

	// activity hint
	packet_IM[114] = 0xff; // for this version should be set to 0xFFFF 
	packet_IM[115] = 0xff; // client starts with 0xFFFF and then uses the servers response

	// fragment len length of body
	packet_IM[116] = 0x54; // The value shall be set to the number of octets of NDRData of the current frame.
	packet_IM[117] = 0x00;

	// fragment num
	packet_IM[118] = 0x00; //The value shall be set to the number of the current fragment
	packet_IM[119] = 0x00;

	// auth proto
	packet_IM[120] = 0x00; // The value shall be set to zero for no authentication

	// serial low
	packet_IM[121] = 0x00; // This field shall be coded as data type Unsigned8. The value contains the low octet of the fragment number of the call.


	// PN_IO Read Implicit
	// ArgsMaximum
	packet_IM[122] = 0xe4;
	packet_IM[123] = 0x0f;
	packet_IM[124] = 0x00;
	packet_IM[125] = 0x00; // = 4068 little endian

	// args length
	packet_IM[126] = 0x40;
	packet_IM[127] = 0x00;
	packet_IM[128] = 0x00;
	packet_IM[129] = 0x00; // 0x00000040 = 64

	// array 
	// max count
	packet_IM[130] = 0xe4;
	packet_IM[131] = 0x0f;
	packet_IM[132] = 0x00;
	packet_IM[133] = 0x00; // = 4068

	// offset
	packet_IM[134] = 0x00;
	packet_IM[135] = 0x00;
	packet_IM[136] = 0x00;
	packet_IM[137] = 0x00;

	// actual count
	packet_IM[138] = 0x40;
	packet_IM[139] = 0x00;
	packet_IM[140] = 0x00;
	packet_IM[141] = 0x00; // 0x00000040 = 64


	// IOReadReqHeader
	//BlockHeader
	// blocktype
	packet_IM[142] = 0x00;
	packet_IM[143] = 0x09;	// 0x0009 IODReadReqHeader
	// blocklength 
	packet_IM[144] = 0x00;
	packet_IM[145] = 0x3c; // starting here the length of the following part
	//block version high
	packet_IM[146] = 0x01;
	// block version low
	packet_IM[147] = 0x00;
	// end Blockheader

	// seqNumber
	packet_IM[148] = 0x00;
	packet_IM[149] = 0x00;

	// ARUUID 16 byte
	packet_IM[150] = 0x00;
	packet_IM[151] = 0x00;
	packet_IM[152] = 0x00;
	packet_IM[153] = 0x00;
	packet_IM[154] = 0x00;
	packet_IM[155] = 0x00;
	packet_IM[156] = 0x00;
	packet_IM[157] = 0x00;
	packet_IM[158] = 0x00;
	packet_IM[159] = 0x00;
	packet_IM[160] = 0x00;
	packet_IM[161] = 0x00;
	packet_IM[162] = 0x00;
	packet_IM[163] = 0x00;
	packet_IM[164] = 0x00;
	packet_IM[165] = 0x00;

	// API
	packet_IM[166] = 0x00;
	packet_IM[167] = 0x00;
	packet_IM[168] = 0x00;
	packet_IM[169] = 0x00;

	if (parameterIndex == PDREALDATASUBMODUL) {
		linkedList_slot* slots = currentDevice->device->slotList;

		for (int i = 0; i < slotparameter->posSlot; i++)
			slots = slots->next;
		// Slotnumber
		packet_IM[170] = slots->slotNumber >> 8;
		packet_IM[171] = slots->slotNumber & 0xFF;

		linkedList_subslot* subslots = slots->subslotList;
		for (int i = 0; i < slotparameter->posSubslot; i++)
			subslots = subslots->next;
		// subslotnumber
		packet_IM[172] = subslots->subslotNumber >> 8;
		packet_IM[173] = subslots->subslotNumber & 0xFF;
	}
	else{
		// Slotnumber
		packet_IM[170] = 0x00;
		packet_IM[171] = 0x00;

		// subslotnumber
		packet_IM[172] = 0x00;
		packet_IM[173] = 0x01;
	}


	// padding
	packet_IM[174] = 0x00;
	packet_IM[175] = 0x00;

	// index can change with every call
	packet_IM[176] = parameterIndex >> 8;
	packet_IM[177] = parameterIndex & 0xFF;

	// record data length
	packet_IM[178] = 0x00;
	packet_IM[179] = 0x00;
	packet_IM[180] = 0x0f;
	packet_IM[181] = 0xa4;

	// target aruuid 16 byte
	packet_IM[182] = 0x00;
	packet_IM[183] = 0x00;

	packet_IM[184] = 0x00;
	packet_IM[185] = 0x00;
	packet_IM[186] = 0x00;
	packet_IM[187] = 0x00;
	packet_IM[188] = 0x00;
	packet_IM[189] = 0x00;
	packet_IM[190] = 0x00;
	packet_IM[191] = 0x00;
	packet_IM[192] = 0x00;
	packet_IM[193] = 0x00;
	packet_IM[194] = 0x00;
	packet_IM[195] = 0x00;
	packet_IM[196] = 0x00;
	packet_IM[197] = 0x00;


	// padding

	packet_IM[198] = 0x00;
	packet_IM[199] = 0x00;
	packet_IM[200] = 0x00;
	packet_IM[201] = 0x00;
	packet_IM[202] = 0x00;
	packet_IM[203] = 0x00;
	packet_IM[204] = 0x00;
	packet_IM[205] = 0x00;

	udp_pHeader.udp_data = malloc(sizeof(char)*UDP_IM_PACKETSIZE);
	for (int i = 42; i < IP_UDP_RPC_IM_PACKETSIZE; i++)
	{
		udp_pHeader.udp_data[i - 42] = packet_IM[i];
	}

	checksum = calculateUDPChecksum(udp_pHeader, packet_IM);
	packet_IM[40] = checksum & 0xFF;
	packet_IM[41] = checksum >> 8;

	if ((fp = pcap_open_live(d->name,		// name of the device
		65536,// portion of the packet to capture. It doesn't matter in this case
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
		)) == NULL) {
		fprintf(stderr,
			"\nUnable to open the adapter. %s is not supported by Npcap\n",
			(char*)d);
		return 2;
	}

	if (pcap_sendpacket(fp,	// Adapter
		packet_IM,				// buffer with the packet
		IP_UDP_RPC_IM_PACKETSIZE					// size
		) != 0) {
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
		return 3;
	}




	pcap_close(fp);
	return 0;
}

/*-----------------------------------------------------------------------------------------*/








/* Help functions*/

// calculate the ip checksum
unsigned short calculateIPChecksum(u_char packet[])
{
	unsigned short CheckSum = 0;
	for (int i = 14; i < 34; i += 2)
	{
		unsigned short Tmp = BytesTo16(packet[i], packet[i + 1]);
		unsigned short Difference = 65535 - CheckSum;
		CheckSum += Tmp;
		if (Tmp > Difference){ CheckSum += 1; }
	}
	CheckSum = ~CheckSum;
	return htons(CheckSum);
}


// helpfunction which converts two hexadecimal numbers to 
u_short BytesTo16(unsigned char X, unsigned char Y)
{
	unsigned short Tmp = X;
	Tmp = Tmp << 8;
	Tmp = Tmp | Y;
	return Tmp;
}


// implement after RPC call is finished

unsigned short calculateUDPChecksum(udp_pseudo_header udp_pseudo_Header, u_char* FinalPacket)
{
	unsigned short CheckSum = 0;
	unsigned short PseudoLength = udp_pseudo_Header.udp_length + 9;// +8;
	// Length of PseudoHeader =
	// Data Length + 8 bytes UDP header
	// + Two 4 byte IP's + 1 byte protocol

	PseudoLength += PseudoLength % 2; //If bytes are not an even number, add an extra.

	u_short Length = udp_pseudo_Header.udp_length; // +8; // This is just UDP + Data length. 
	//needed for actual data in udp header

	u_char* PseudoHeader;
	if ((PseudoHeader = malloc(sizeof(u_char)*(PseudoLength))) == NULL)
	{
		printf_s("Memory allocation failed");
		return 3;
	}

	for (int i = 0; i < PseudoLength; i++){ PseudoHeader[i] = 0x00; }//Init

	PseudoHeader[0] = udp_pseudo_Header.protocoll; // Protocol

	memcpy((void*)(PseudoHeader + 1), (void*)(FinalPacket + 26), 8); // Source and Dest IP

	Length = htons(Length); // Length is not network byte order yet
	memcpy((void*)(PseudoHeader + 9), (void*)&Length, 2); //Included twice
	memcpy((void*)(PseudoHeader + 11), (void*)&Length, 2);
	memcpy((void*)(PseudoHeader + 13), (void*)(FinalPacket + 34), 2);//Source Port
	memcpy((void*)(PseudoHeader + 15), (void*)(FinalPacket + 36), 2); // Dest Port


	memcpy((void*)(PseudoHeader + 17), (void*)udp_pseudo_Header.udp_data, udp_pseudo_Header.udp_length - 8);

	for (int i = 0; i < PseudoLength; i += 2)
	{
		u_short Tmp = PseudoHeader[i] << 8 | PseudoHeader[i + 1];
		u_short Difference = 65535 - CheckSum;
		CheckSum += Tmp;
		if (Tmp > Difference){ CheckSum += 1; }
	}
	CheckSum = ~CheckSum; //One's complement
	free(PseudoHeader);
	return CheckSum;
}


// remove the char rem from a string
void stripEnter(char *s, char* rem) {
	char *p2 = s;
	while (*s != '\0') {
		if (*s != *rem) {
			*p2++ = *s++;
		}
		else {
			++s;
		}
	}
	*p2 = '\0';
}

// returns true if strings are the same, false in other cases
bool mystrcmp(char *s, char *d)
{
	int i, count_S, count_D;
	if (s == NULL || d == NULL)
	{
		return true;
	}
	for (count_S = 0; s[count_S] != '\0'; count_S++);
	for (count_D = 0; d[count_D] != '\0'; count_D++);
	if (count_D != count_S)
		return false;
	i = 0;
	while (i != count_S && i != count_D)
	{
		if (s[i] < d[i])
			return false;
		else if (s[i] > d[i]){
			return false;
		}
		i++;
		if (s[i] == '\0' && d[i] == '\0')
		{
			return true;
		}
		if (s[i] == '\0')
		{
			return false;
		}
		if (d[i] == '\0')
		{
			return false;
		}
	}
	return true;
}

// check if every device set the finished bool to true
bool checkDevicesFullExtracted(linked_list_t* deviceList)
{
	if (deviceList == NULL)
		return false;

	while (deviceList != NULL){
		if (!deviceList->finished)
		{
			return false;
		}
		deviceList = deviceList->next;
	}

	return true;
}

// compare the Mac Addresses of two devices
bool compareMacAddress(mac_address file, mac_address packet)
{
	if (file.byte1 != packet.byte1)
		return false;
	if (file.byte2 != packet.byte2)
		return false;
	if (file.byte3 != packet.byte3)
		return false;
	if (file.byte4 != packet.byte4)
		return false;
	if (file.byte5 != packet.byte5)
		return false;
	if (file.byte6 != packet.byte6)
		return false;

	return true;
}

// create a struct and fill the lists and strings with NULL
datasheet* createDatasheet()
{
	datasheet* ds;
	if ((ds = malloc(sizeof(datasheet))) == NULL)
		return NULL;

	ds->deviceRoleDetail = 0x00;
	ds->nameOfStation = NULL;
	ds->deviceType = NULL;
	ds->slotList = NULL;
	ds->orderId = NULL;
	ds->hardwareRevison = NULL;
	ds->udpPort = 0x0000;

	return ds;

}

// compare to ip addresses
bool compareIPaddr(ip_address file, ip_address device)
{
	if (file.byte1 != device.byte1)
		return false;
	if (file.byte2 != device.byte2)
		return false;
	if (file.byte3 != device.byte3)
		return false;
	if (file.byte4 != device.byte4)
		return false;


	return true;
}





