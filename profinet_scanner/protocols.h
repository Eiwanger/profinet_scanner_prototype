
#include <pcap.h>
#define DCP_PACKETSIZE 46
#define IP_UDP_RPC_PACKETSIZE 198
#define UDP_PACKETSIZE 164
#define IP_UDP_RPC_IM_PACKETSIZE 206
#define UDP_IM_PACKETSIZE 172


// values which aren't define shall be reserved values

// define Options for profinet dcp
#define OPT_Reserved00						0x00
#define OPT_IPOption						0x01
#define OPT_DevicePropertiesOption			0x02
#define OPT_DHCPOption						0x03
#define OPT_ControlOption					0x05
#define OPT_DeviceInitiativeOption			0x06
#define OPT_AllSelectorOption				0xFF

// define suboptions for IPOption
#define SUBOPT_IPO_MACAddress				0x01
#define SUBOPT_IPO_IPParameter				0x02
#define SUBOPT_IPO_FUllIPSuite				0x03

// define suboptions for DevicePropertiesOption
#define SUBOPT_DPO_DeviceVendor				0x01
#define SUBOPT_DPO_NameOfStation			0x02
#define SUBOPT_DPO_DeviceID					0x03
#define SUBOPT_DPO_DeviceRole				0x04
#define SUBOPT_DPO_DeviceOptions			0x05
#define SUBOPT_DPO_AliasName				0x06
#define SUBOPT_DPO_DeviceInstance			0x07
#define SUBOPT_DPO_OEMDeviceID				0x08
#define SUBOPT_DPO_StandardGateway			0x09

// define suboptions for DHCPOption
#define SUBOPT_DHCP_HostName					12		//decimal values		
#define SUBOPT_DHCP_VendorSpecificInformation	43
#define SUBOPT_DHCP_ServerIdentifier			54
#define SUBOPT_DHCP_ParameterRequestList		55
#define SUBOPT_DHCP_ClassIdentifier				60
#define SUBOPT_DHCP_DHCPClientIdentifier		61
#define SUBOPT_DHCP_FQDN						81		// Fully qualified Domain name
#define SUBOPT_DHCP_UUIDbasedClientIdentifier	97

// define suboptions for ControllOption
#define SUBOPT_CO_Start						0x01
#define SUBOPT_CO_Stop						0x02
#define SUBOPT_CO_Signal					0x03
#define SUBOPT_CO_Response					0x04
#define SUBOPT_CO_FactoryReset				0x05
#define SUBOPT_CO_ResetToFactory			0x06

// define suboptions for DeviceInitiativeOption
#define SUBOPT_DIO_DeviceInitiative			0x01

// define suboptions for AllSelectorOption
#define SUBOPT_ASO_AllSelector				0xFF


// defines for send packet IM
#define IM0FILTERDATA				0xf840
#define PDREALDATA					0xf841
#define PDREALDATASUBMODULEXT		0x8027
#define PDREALDATASUBMODUL			0x802a
#define REALIDENTIFICATIONDATA		0xf000
#define IM0							0xaff0
#define IM1							0xaff1
#define IM2							0xaff2
#define IM3							0xaff3

#define PDINTERFACEDATAREAL			0x0240

/* 4 bytes IP address */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

// own code

// 6 bytes of the mac address
typedef struct mac_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac_address;

// 14 byte 
typedef struct ethernet_header{
	mac_address dest_addrK;  // Destination mac address 6 byte
	mac_address src_addrK;   // Source mac address 6 byte
	u_short	type_field;      // type field 2 byte
}ethernet_header;




// simply for less work to pass variables
typedef struct udp_pseudo_header{
	u_char srcIp1;	// first byte source ip
	u_char srcIp2;	// second byte source ip
	u_char srcIp3;	// third byte source ip
	u_char srcIp4;	// fourth byte source ip

	u_char destIp1;	// first byte destination ip
	u_char destIp2;	// second byte destination ip
	u_char destIp3;	// third byte destination ip
	u_char destIp4;	// fourth byte destination ip

	u_char protocoll; 

	u_char srcPort1;
	u_char srcPort2;

	u_char destPort1;
	u_char destPort2;

	u_short udp_length;

	u_char* udp_data;
	// implement rest of udp_data

}udp_pseudo_header;


typedef struct rpc_objectUUID{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
	u_char byte7;
	u_char byte8;
	u_char byte9;
	u_char byte10;
	u_char byte11;
	u_char byte12;
	u_char byte13;
	u_char byte14;
	u_char byte15;
	u_char byte16;
}rpc_objectUUID;

typedef struct rpc_interfaceUUID{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
	u_char byte7;
	u_char byte8;
	u_char byte9;
	u_char byte10;
	u_char byte11;
	u_char byte12;
	u_char byte13;
	u_char byte14;
	u_char byte15;
	u_char byte16;
}rpc_interfaceUUID;

typedef struct arUUID{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
	u_char byte7;
	u_char byte8;
	u_char byte9;
	u_char byte10;
	u_char byte11;
	u_char byte12;
	u_char byte13;
	u_char byte14;
	u_char byte15;
	u_char byte16;
}arUUID;

typedef struct rpc_activity{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
	u_char byte7;
	u_char byte8;
	u_char byte9;
	u_char byte10;
	u_char byte11;
	u_char byte12;
	u_char byte13;
	u_char byte14;
	u_char byte15;
	u_char byte16;
}rpc_activity;

typedef struct rpc_serverBootTime{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}rpc_serverBootTime;

typedef struct rpc_interfaceVersion{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}rpc_interfaceVersion;

typedef struct rpc_sequenceNum{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}rpc_sequenceNum;




typedef struct epm_handle{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
	u_char byte7;
	u_char byte8;
	u_char byte9;
	u_char byte10;
	u_char byte11;
	u_char byte12;
	u_char byte13;
	u_char byte14;
	u_char byte15;
	u_char byte16;
	u_char byte17;
	u_char byte18;
	u_char byte19;
	u_char byte20;
}epm_handle;

typedef struct epm_numberOfEntries{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}epm_numberOfEntries;

typedef struct epm_maxCount{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}epm_maxCount;

typedef struct epm_offset{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}epm_offset;

typedef struct epm_actualCount{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}epm_actualCount;

typedef struct epm_returnCode{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}epm_returnCode;




typedef struct epm_referentID{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}epm_referentID;





typedef struct epm_length{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}epm_length;

typedef struct epm_floorLength
{
	u_char byte1;
	u_char byte2;
}epm_floorLength;

// floor 1&2
typedef struct epm_floorUUID{
	epm_floorLength LHS_length;
	u_char protocol;
	rpc_objectUUID UUID;		// has nothing to do with rpc, is just the same size
	u_short version;
	epm_floorLength RHS_length;
	u_short versionMinor;
}epm_floorUUID;

// floor 3
typedef struct epm_RPC_prot{
	epm_floorLength LHS_length;
	u_char protocol;
	epm_floorLength RHS_length;
	u_short versionMinor;
}epm_RPC_prot;

// floor 4
typedef struct epm_UDP_prot{
	epm_floorLength RHS_length;
	u_short udp_port;
	epm_floorLength LHS_length;
	u_char protocol;
}epm_UDP_prot;

// floor 5
typedef struct epm_IP_prot{
	epm_floorLength LHS_length;
	u_char protocol;
	epm_floorLength RHS_length;
	ip_address ipaddress;
}epm_IP_prot;


typedef struct epm_annotationOffset{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} epm_annotationOffset;

typedef struct epm_annotationLength{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} epm_annotationLength;

typedef struct epm_towerPointer{
	epm_referentID referentID;
	epm_annotationOffset annotationOffset;
	epm_annotationLength annotationLength;
	u_char annotation[64];  // 64 byte of data
	epm_length length1;
	epm_length length2;
	u_short numberOfFloors;
	epm_floorUUID floor1;	
	epm_floorUUID floor2;
	epm_RPC_prot floor3_rpc;
	epm_UDP_prot floor4_udp;
	epm_IP_prot floor5_ip;


}epm_towerPointer;

typedef struct epm_entryService{
	rpc_objectUUID oUUID;
	epm_towerPointer towerPointer;
}epm_entryService;


typedef struct epm_entries
{
	epm_maxCount maxCount;
	epm_offset offset;
	epm_actualCount actualCount;
	epm_entryService entryService;
}epm_entries;

// endpointmapper response
typedef struct endpointMapperResp{
	epm_handle handle;
	epm_numberOfEntries numEntries;
	epm_entries entries;
	epm_returnCode returnCode;
} endpointMapperResp;



typedef struct DCE_RPC_EM_Call{
	u_char version;
	u_char packetType;
	u_char flag1;
	u_char flag2;
	// Data Representation
	u_char character_ByteOrder;
	u_char floatingPoint;
	u_char dataRep;
	u_char serialHigh;
	rpc_objectUUID oUUID;
	rpc_interfaceUUID iUUID;
	rpc_activity activity;
	rpc_serverBootTime serverBootTime;
	rpc_interfaceVersion interfaceVer;
	rpc_sequenceNum sequenceNum;
	u_short operationNumber;
	u_short interfaceHint;
	u_short activityHint;
	u_short fragmentLen;
	u_short fragmentNum;
	u_char authProto;  // authetification protocoll
	u_char serialLow;
	endpointMapperResp epm_response;
}DCE_RPC_EM_CALL;

typedef struct DCE_RPC_IM_Call{
	u_char version;
	u_char packetType;
	u_char flag1;
	u_char flag2;
	// Data Representation
	u_char character_ByteOrder;
	u_char floatingPoint;
	u_char dataRep;
	u_char serialHigh;
	rpc_objectUUID oUUID;
	rpc_interfaceUUID iUUID;
	rpc_activity activity;
	rpc_serverBootTime serverBootTime;
	rpc_interfaceVersion interfaceVer;
	rpc_sequenceNum sequenceNum;
	u_short operationNumber;
	u_short interfaceHint;
	u_short activityHint;
	u_short fragmentLen;
	u_short fragmentNum;
	u_char authProto;  // authetification protocoll
	u_char serialLow;

	// ReadImplicit
	// just set up a u_char* with the length which is described in u_short fragmentLen 
}DCE_RPC_IM_CALL;

typedef struct Blockheader{
	u_short blocktype;
	u_short blocklength;
	u_char blockVersionHigh;
	u_char blockVersionLow;
}Blockheader;

typedef struct pn_ReadImplicit{
	u_char errorCode2;
	u_char errorCode1;
	u_char errorDecode;
	u_char errorCode;

	u_char argsLength[4];

	// array
	u_char maxCount[4];
	u_char offset[4];
	u_char actualCount[4];
	// end array

	// IODReadResHeader
		// Blockheader
	Blockheader blockheader;
		// end blockheader
	u_short seqNumber;
	arUUID arUUID;
	u_char API[4];
	u_short slotNumber;
	u_short subslotNumber;
	u_short padding;
	u_short index;
	u_char recordDataLength[4];
	u_short additionalValue1;
	u_short additionalValue2;
	u_char padding_end[20];
	// end IODReadResHeader
	u_char nextPos;

}pn_ReadImplicit;


typedef struct xid{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}xid;

typedef struct profinet_prot{
	u_short frameId;
	u_char serviceId;
	u_char serviceType;
	xid xid;
	u_short reserved;
	u_short dataLength;
}profinet_prot;

typedef struct pn_data{
	u_char option;			// 1 byte
	u_char suboption;		// 1 byte
	u_short blocklength;	// 2 byte
	u_short blockinfo;		// 2 byte

}pn_data;


typedef struct multipleBlockHeader{
	Blockheader blockheader;
	u_short padding;
	u_char API[4];
	u_short slotnumber;
	u_short subslotnumber;

}multipleBlockHeader;




// slot of IM0FilterData
typedef struct SubSlot{
	u_short subslotNumber;
	u_char submoduleIdentNumber[4];
}SubSlot;

typedef struct Slot{
	u_short slotNumber;
	u_char moduleIdentNumber[4];
	u_short numberOfSubmodules;

	SubSlot** subslots;
}Slot;

typedef struct Slot_P{
	u_short slotNumber;
	u_char moduleIdentNumber[4];
	u_short numberOfSubmodules;

	u_char nextPos;
	//SubSlot* subslots;
}Slot_P;


typedef struct IM0FilterDataModul{
	Blockheader blockheader;
	u_short numberOfAPIs;
	u_char API[4];
	u_short numberOfSubmodules;
	//Slot* slots;

}IM0FilterDataModul;

typedef struct realIdentificationData{
	Blockheader blockheader;
	u_short numberOfAPIs;
	u_char API[4];
	u_short numberOfSlots;
	u_char nextPos;
	// slots
}realIdentificationData;


typedef struct IM0Data{
	Blockheader blockheader;
	u_char vendorIDHigh;
	u_char vendorIDLow;
	u_char orderID[20];
	u_char IMserialNumber[16];
	u_short hardwareRevision;
	u_char IMRevisionPrefix;
	u_char IMSWRevisionFuncitonalEnhancement;
	u_char IMSWRevisionBugfix;
	u_char IMSWRevisionInternalChange;  // IMRevisionPrefix + IMSWRevisionFuncitonalEnhancement + IMSWRevisionBugfix + IMSWRevisionInternalChange == softwareversion
	u_short IMRevisionCounter;
	u_short IMProfileID;
	u_short IMProfileSpecificType;
	u_char IMVersionMajor;
	u_char IMVersionMinor;
	u_short IMSupported;
}IM0Data;

typedef struct IM1Data{
	Blockheader blockheader;
	u_char IM_Tag_Function[32];
	u_char IM_Tag_Location[22];
}IM1Data;

typedef struct IM2Data{
	Blockheader blockheader;
	u_char IM_Date[16];
}IM2Data;

typedef struct IM3Data{
	Blockheader blockheader;
	u_char IM_Descriptor[54];
}IM3Data;


typedef struct PDInterfaceDataReal{
	Blockheader blockheader;
	u_char lengthOfOwnChassisID;


}PDInterfaceDataReal;


typedef struct pdPortData{
	Blockheader blockheader;
	u_short padding;
	u_short slotnumber;
	u_short subslotnumber;
	u_char lengthOwnPortID;
	u_char ownPortID[8]; // just hope that there is no longer port id
	u_char numberOfPeers;

	u_char pos; // not part of the packet, just for pointer purposes
}pdPortData;

typedef struct pdPortDataWithPeer{
	u_short padding;
	u_char lengthPeerPortID;
	u_char peerPortID[8]; // just hope that there is no longer port id
	u_char lengthPeerChassisID;
}pdPortDataWithPeer;

typedef struct pdPortDataWithoutPeer{
	u_short padding0;
	u_short MAUType;
	u_short padding1;
	u_char domainBoundary[4];
	u_char mulitcastBoundary[4];
	u_short portState;
	u_short padding2;
	u_char mediaType[4];
}pdPortDataWithoutPeer;




typedef struct linkedList_subslot{
	u_short subslotNumber;
	u_char submoduleIdentNumber[4];
	u_char* peerChassisID;
	mac_address* peerMacAddress;

	struct linkedList_subslot* next;

}linkedList_subslot;

typedef struct linkedList_slot{
	u_short slotNumber;
	u_char moduleIdentNumber[4];
	u_short numberOfSubmodules;


	linkedList_subslot* subslotList;

	struct linkedList_slot* next;

}linkedList_slot;


// endstruct, form where all the data should be stored
typedef struct datasheet{
	ip_address deviceIp;
	ip_address subnetmask;
	mac_address deviceMACaddress;
	ip_address defaultGateway;

	u_short vendorId;
	u_short deviceId;
	u_char deviceRoleDetail;
	char* deviceVendor;  // allocate the size of the array according to the size of the blocklength - 2
	char* nameOfStation;

	char* deviceType;
	char* version;
	char* orderId;
	char* hardwareRevison;
	u_short udpPort;

	linkedList_slot* slotList;
	int numberOfSlots;
	rpc_objectUUID objectUUID;
}datasheet;

typedef struct linked_list{
	int index;
	datasheet* device;

	// parameters which will be extracet for further use
	epm_handle rpc_handle;
	rpc_serverBootTime sBootTime;
	rpc_sequenceNum sequenceNum;

	bool finished;

	struct linked_list* next;

}linked_list_t;

typedef struct threadData{
	pcap_if_t *alldevs;
	int numberOfAdapters;

	linked_list_t* first;
	int devCount;

	ip_address ownIp;
	mac_address ownMac;
	ip_address subnetmask;

	ip_address* targetIP;
	int numberOfIPDev;
	mac_address* defaultGatewayMAC;
	
}threadData_t;

typedef struct slotParameter{
	int posSlot;
	int posSubslot;
}slotParameter;