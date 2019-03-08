/*
#include <pcap.h>
#include "stdafx.h"

// endstruct where all the data should be stored
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


}datasheet;

typedef struct node{

	datasheet* device;
	node_t * next;
}node_t;

typedef struct threadData{
	pcap_if_t *alldevs;
	int numberOfAdapters;

	node_t* first;
	//datasheet* deviceList;
}threadData_t;
*/