#include "stdafx.h"

//u_short identnmb = 0;

// send a RPC Endpointmapper packet to a given ip
// @param threadData -> struct which contains necessary information for the call
// @param firstCall -> states if the rpc call is the first or the second one. The second one needs the handle 
int sendPacket_RPC_rem(threadData_t* threadData, bool firstCall)
{
	pcap_t *fp;
	u_char packet_ip[IP_UDP_RPC_PACKETSIZE];

	char errbuf[PCAP_ERRBUF_SIZE];

	int i = 0;
	pcap_if_t *d;

	// Jump to the selected adapter
	//inum = 7;
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

	if (!firstCall)
		for (int i = 0; i < threadData->numberOfIPDev; i++, currentDevice = currentDevice->next);

	// address of router

	packet_ip[0] = threadData->defaultGatewayMAC->byte1;
	packet_ip[1] = threadData->defaultGatewayMAC->byte2;
	packet_ip[2] = threadData->defaultGatewayMAC->byte3;
	packet_ip[3] = threadData->defaultGatewayMAC->byte4;
	packet_ip[4] = threadData->defaultGatewayMAC->byte5;
	packet_ip[5] = threadData->defaultGatewayMAC->byte6;


	// set mac source address
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
	packet_ip[18] = identnmb >> 8;
	//packet_IM[19] = 0x0a;
	packet_ip[19] = identnmb & 0xFF;
	identnmb++;

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
	// use target ip from console input
	if (!firstCall){
			packet_ip[30] = currentDevice->device->deviceIp.byte1;
			packet_ip[31] = currentDevice->device->deviceIp.byte2;
			packet_ip[32] = currentDevice->device->deviceIp.byte3;
			packet_ip[33] = currentDevice->device->deviceIp.byte4;

	}
	else{
		packet_ip[30] = threadData->targetIP[threadData->numberOfIPDev].byte1;
		packet_ip[31] = threadData->targetIP[threadData->numberOfIPDev].byte2;
		packet_ip[32] = threadData->targetIP[threadData->numberOfIPDev].byte3;
		packet_ip[33] = threadData->targetIP[threadData->numberOfIPDev].byte4;
	}
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
	packet_ip[69] = 0xe1; // UID_EPMap_Interface  E1AF8308-5D1F-11C9  --> little endian?

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
	// it doesn't change anything

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
	// implement a creation of a new seq number with the global seqNumber counter
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

	if (currentDevice){

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
	}
	else{

		packet_ip[174] = 0x00;
		packet_ip[175] = 0x00;
		packet_ip[176] = 0x00;
		packet_ip[177] = 0x00;
		packet_ip[178] = 0x00;
		packet_ip[179] = 0x00;
		packet_ip[180] = 0x00;
		packet_ip[181] = 0x00;
		packet_ip[182] = 0x00;
		packet_ip[183] = 0x00;
		packet_ip[184] = 0x00;
		packet_ip[185] = 0x00;
		packet_ip[186] = 0x00;
		packet_ip[187] = 0x00;
		packet_ip[188] = 0x00;
		packet_ip[189] = 0x00;
		packet_ip[190] = 0x00;
		packet_ip[191] = 0x00;
		packet_ip[192] = 0x00;
		packet_ip[193] = 0x00;
	}

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

	// Open the adapter
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

	// send function
	if (pcap_sendpacket(fp,	// Adapter
		packet_ip,				// buffer with the packet
		IP_UDP_RPC_PACKETSIZE					// size
		) != 0) {
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
		return 3;
	}



	// close the adapter
	pcap_close(fp);
	return 0;

}














// send a implicit read request
// @param  threadData -> struct which contains necessary information for the call
// @param parameterIndex -> defined value, states which call it is
// @param slotparameter -> struct which contains the counter for slot and subslot
// @param layer -> states if the function is called on layer 2 or layer 3
int sendpacket_IM_rem(threadData_t* threadData, u_short parameterIndex, slotParameter* slotparameter, int layer)
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

	for (int i = 0; i < threadData->numberOfIPDev; i++, currentDevice = currentDevice->next);

	// remote, so it is the address of the default gateway
	if (layer == 3){
		packet_IM[0] = threadData->defaultGatewayMAC->byte1;
		packet_IM[1] = threadData->defaultGatewayMAC->byte2;
		packet_IM[2] = threadData->defaultGatewayMAC->byte3;
		packet_IM[3] = threadData->defaultGatewayMAC->byte4;
		packet_IM[4] = threadData->defaultGatewayMAC->byte5;
		packet_IM[5] = threadData->defaultGatewayMAC->byte6;
	}
	else{
		packet_IM[0] = currentDevice->device->deviceMACaddress.byte1;
		packet_IM[1] = currentDevice->device->deviceMACaddress.byte2;
		packet_IM[2] = currentDevice->device->deviceMACaddress.byte3;
		packet_IM[3] = currentDevice->device->deviceMACaddress.byte4;
		packet_IM[4] = currentDevice->device->deviceMACaddress.byte5;
		packet_IM[5] = currentDevice->device->deviceMACaddress.byte6;
	}

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
	packet_IM[36] = currentDevice->device->udpPort >> 8;		
	packet_IM[37] = currentDevice->device->udpPort &0xFF;

//	packet_IM[36] = 0x88;
//	packet_IM[37] = 0x94;

	// Length
	int udp_len = UDP_IM_PACKETSIZE;

	packet_IM[38] = htons(udp_len) & 0xFF;
	packet_IM[39] = htons(udp_len) >> 8;


	// checksum of udp header set to 0 first
	packet_IM[40] = 0x00;
	packet_IM[41] = 0x00;



	// calculation of udp header
	udp_pseudo_header udp_pHeader;

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
	if (layer == 3){
		packet_IM[62] = currentDevice->device->objectUUID.byte13;
		packet_IM[63] = currentDevice->device->objectUUID.byte14;

		// vendor id
		packet_IM[64] = currentDevice->device->objectUUID.byte15;
		packet_IM[65] = currentDevice->device->objectUUID.byte16;
	}
	else
	{
		// device id 
		packet_IM[62] = currentDevice->device->deviceId >> 8;
		packet_IM[63] = currentDevice->device->deviceId & 0xFF;

		// vendor id
		packet_IM[64] = currentDevice->device->vendorId >> 8;
		packet_IM[65] = currentDevice->device->vendorId & 0xFF;
	}

	// interfaceUUID  now change for I&M
	packet_IM[66] = 0x01;
	packet_IM[67] = 0x00;
	packet_IM[68] = 0xa0;
	packet_IM[69] = 0xde; // PNIO (Device Interface)  dea00001-6c97-11d1-8271-00a02442df7d  --> little endian?

	packet_IM[70] = 0x97;
	packet_IM[71] = 0x6c;
	packet_IM[72] = 0xd1;
	packet_IM[73] = 0x11;

	packet_IM[74] = 0x82;	// big endian
	packet_IM[75] = 0x71;

	packet_IM[76] = 0x00;
	packet_IM[77] = 0xa0;
	packet_IM[78] = 0x24;
	packet_IM[79] = 0x42;
	packet_IM[80] = 0xdf;
	packet_IM[81] = 0x7d;

	// Activity


	packet_IM[82] = 0x80;
	packet_IM[83] = 0xd2;  // docu says that the RPCActivityUUID will be generated for each AR
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
	// plan to overwrite the 0 with the answer of the device

	packet_IM[98] = 0x00;
	packet_IM[99] = 0x00;
	packet_IM[100] = 0x00;
	packet_IM[101] = 0x00;

	// interface version
	packet_IM[102] = 0x01;
	packet_IM[103] = 0x00;
	packet_IM[104] = 0x00;
	packet_IM[105] = 0x00;

	// sequence num // for each request has to a unique number created
	// the request has to be new use seqNum counter
	// try if just the complement works -> works!
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
	else if (parameterIndex == IM0)
	{
		linkedList_slot* slots = currentDevice->device->slotList;
		for (int i = 0; i < slotparameter->posSlot; i++)
			slots = slots->next;
		// Slotnumber
		packet_IM[170] = slots->slotNumber >> 8;
		packet_IM[171] = slots->slotNumber & 0xFF;

		// subslotnumber
		packet_IM[172] = 0x00;
		packet_IM[173] = 0x01;
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

	// index changes with every call

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

	//printf_s("Try to send packet:\n");

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














// function which is called for every incoming packet which comes through the filter
// @param param is a pointer -> here it points to a threadData struct
// @param header -> pointer to link header
// @param pkt_data -> pointer to the packet 
void packet_handler_IP_rem(u_char* param, const struct pcap_pkthdr *header, const u_char *pkt_data)
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
	// retireve the position of the ip header
	ih = (ip_header *)(pkt_data + 14); //length of ethernet header


	// retireve the position of the udp header
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *)((u_char*)ih + ip_len);

	// convert from network byte order to host byte order
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);

	dcerpccall = (DCE_RPC_EM_CALL*)((u_char*)uh + 8);

	if (ih->proto != 0x11)	// not a udp packet
		return;

	if (dport != 0x8894)	// not a rpc packet
		return;

	// check if its a read implicit call
	if (dcerpccall->operationNumber == 0x0005)
	{
		packet_handler_ImplicitRead(threadData, header, pkt_data);
	}

	if (!(sport == dport && sport == 34964))
	{
		// exit, this packet has no use for me
		return;
	}



	if (dcerpccall->packetType == 0x00 || dcerpccall->packetType == 0x03){
		return; // its the request or a fault
	}

	if (dcerpccall->epm_response.numEntries.byte4 != 0x01 && dcerpccall->epm_response.numEntries.byte1 != 0x01)
	{
		return; // empty packet?
	}

	// create temporary space
	recData = createDatasheet();
	recData->slotList = NULL;

	int offset = 0;
	recData->deviceType = cutDataFromString(dcerpccall->epm_response.entries.entryService.towerPointer.annotation, &offset, false);
	recData->orderId = cutDataFromString(dcerpccall->epm_response.entries.entryService.towerPointer.annotation, &offset, false);
	char* versions = cutDataFromString(dcerpccall->epm_response.entries.entryService.towerPointer.annotation, &offset, true);


	recData->hardwareRevison = cutHardwareRevision(versions);
	recData->udpPort = ntohs(dcerpccall->epm_response.entries.entryService.towerPointer.floor4_udp.udp_port);

	recData->version = cutSoftVersion(versions);


	recData->objectUUID = dcerpccall->epm_response.entries.entryService.oUUID;
	recData->deviceId = ((recData->objectUUID.byte13 << 8) & 0xFF00) | (recData->objectUUID.byte14 & 0xFF);
	recData->vendorId = ((recData->objectUUID.byte15 << 8) & 0xFF00) | (recData->objectUUID.byte16 & 0xFF);


	// everybody has a mac address // its the address of the router
	recData->deviceMACaddress.byte1 = ethh->src_addrK.byte1;
	recData->deviceMACaddress.byte2 = ethh->src_addrK.byte2;
	recData->deviceMACaddress.byte3 = ethh->src_addrK.byte3;
	recData->deviceMACaddress.byte4 = ethh->src_addrK.byte4;
	recData->deviceMACaddress.byte5 = ethh->src_addrK.byte5;
	recData->deviceMACaddress.byte6 = ethh->src_addrK.byte6;

	recData->deviceIp.byte1 = ih->saddr.byte1;
	recData->deviceIp.byte2 = ih->saddr.byte2;
	recData->deviceIp.byte3 = ih->saddr.byte3;
	recData->deviceIp.byte4 = ih->saddr.byte4;



	/* convert the timestamp to readable format */
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	//print timestamp and length of the packet
	printf("%s.%.6d len:%d  %d.%d.%d.%d\n", timestr, header->ts.tv_usec, header->len, ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);


	// check first, if it is NULL malloc the first box
	linked_list_t* tmpList = threadData->first;
	recData->deviceIp = ih->saddr;
	


	if (tmpList == NULL){
		threadData->first = malloc(sizeof(linked_list_t));
		if (!threadData->first)
		{
			printf("Error allocating memory for linkedList");
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

		threadData->first->rpc_handle = dcerpccall->epm_response.handle;

		threadData->devCount++;


	}
	else
	{

		while (tmpList != NULL)
		{

			//if (compareMacAddress(tmpList->device->deviceMACaddress, recData->deviceMACaddress) && compareIPaddr(recData->deviceIp, tmpList->device->deviceIp))
			if (compareIPaddr(recData->deviceIp, tmpList->device->deviceIp))
			{
				tmpList->device->deviceType = recData->deviceType;
				tmpList->device->orderId = recData->orderId;
				tmpList->device->version = recData->version;
				tmpList->device->hardwareRevison = recData->hardwareRevison;
				tmpList->device->udpPort = recData->udpPort;
				tmpList->device->objectUUID = recData->objectUUID;
				tmpList->device->deviceId = recData->deviceId;
				tmpList->device->vendorId = recData->vendorId;

				tmpList->rpc_handle = dcerpccall->epm_response.handle;
				
				return;
			}
			tmpList = tmpList->next;
		}

		// create new datasheet

		add_to_list(threadData->first, recData, &dcerpccall->epm_response.handle);
		threadData->devCount++;
	}

	t1_G = clock();
}



// function which captures packets 
// @param threadData -> pointer to a threadData struct, which contains necessary information for the function
int captureIPPackets_rem(threadData_t* threadData){
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


	// Check the link layer. We support only Ethernet for simplicity.
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		return -1;
	}

	if (d->addresses != NULL)
		// Retrieve the mask of the first address of the interface
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		// If the interface is without addresses we suppose to be in a C class network
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


	// start the capture
	// the second parameter is a packet count, if it is reached, loop will be terminated 0 or -1 equals infinity
	t1_G = clock();
	HANDLE loopBreakThread = CreateThread(NULL, 0, loopTimerThread, NULL, 0, lpExitCode);
	if (loopBreakThread == NULL)
	{
		printf("Error creating loopBreakThread");
		return -1;
	}
	pcap_loop(adhandle, 0, packet_handler_IP_rem, (u_char*)threadData);

	WaitForSingleObject(loopBreakThread, INFINITE);

	pcap_close(adhandle);
	return 0;
}


// function for threading
DWORD WINAPI sniffer_thread_remote(LPVOID lpParameter)
{
	captureIPPackets_rem(lpParameter);
	return 0;
}


// function to check the given ip
// @param targetIP -> a string with the form xxx.xxx.xxx.xxx-xxx
// @param threadData -> pointer to threadData struct, place to store the parsed ip address
int checkIP(char* targetIP, threadData_t* threadData)
{
	if (targetIP[0] == 0)	// empty
		return -1;

	int length;
	for (length = 0; targetIP[length] != '\n'; length++);
	if (length < 7)
	{
		printf("Target IP to short\n");
		return -1;
	}



	char* token;
	char* rangeToken;
	int endrange;
	char* copyIP;
	char* context = malloc(128);
	if (context == NULL){
		printf("Error allocating memory for context in checkIP");
		return -1;
	}
	int address[4];

	if ((copyIP = malloc(sizeof(char) * (strlen(targetIP) + 1))) == NULL)
	{
		printf("Error allocating memory for ip buffer");
		return -1;
	}

	strcpy_s(copyIP, strlen(targetIP) + 1, targetIP);

	char* searchdot = ".";
	char* rangeSearch = "-";
	bool isrange = false;

	// check if the ip is a range
	for (int i = 0; targetIP[i] != '\n'; i++){
		if (targetIP[i] == '-'){
			isrange = true;
		}
	}

	if ((token = malloc(sizeof(char) * 4)) == NULL)
	{
		printf("Error allocating memory for ip token");
		return -1;
	}

	if ((rangeToken = malloc(sizeof(char) * 4)) == NULL)
	{
		printf("Error allocating memory for ip range token");
		return -1;
	}

	int a = 0;
	token = strtok_s(copyIP, searchdot, &context);
	do{
		address[a] = (int)strtol(token, NULL, 10); // 10 for decimal // get the last address of the range

		a++;
	} while ((token = strtok_s(NULL, searchdot, &context)) != NULL && a < 4);

	strcpy_s(copyIP, strlen(targetIP) + 1, targetIP);
	// debug
	if (isrange)
	{
		token = strtok_s(copyIP, rangeSearch, &context);
		rangeToken = strtok_s(NULL, rangeSearch, &context);
		endrange = (int)strtol(rangeToken, NULL, 10); // 10 for decimal // get the last address of the range
	}
	else{
		endrange = address[3];
	}

	// calc range
	int range = endrange - address[3];


	threadData->targetIP = malloc(sizeof(ip_address) * (range+1));
	if (!threadData->targetIP)
	{
		printf("Error allocating memory for ip address range");
		return false;
	}
	int i = 0;

	do{
		threadData->targetIP[i].byte1 = (u_char)address[0];
		threadData->targetIP[i].byte2 = (u_char)address[1];
		threadData->targetIP[i].byte3 = (u_char)address[2];
		threadData->targetIP[i].byte4 = (u_char)(address[3] + i);
		i++;
	} while (i <= range);

	return range;
}