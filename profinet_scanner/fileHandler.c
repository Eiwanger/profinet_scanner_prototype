#include "stdafx.h"
#include "filehandler.h"


int writeToFile(datasheet* deviceInfo, char* cFilename)
{
	FILE *fp;
	bool exists;
	errno_t err;

	// Path to safe location
	// change for every device
	// char* filepath = "C:\\Users\\q419840\\Documents\\TP-S-41\\ScannerFiles\\"; //54 chars
	char filename[MAX_FILENAME_LENGTH];
	//create string with filename and path
	sprintf_s(filename, MAX_FILENAME_LENGTH, "%s", cFilename);

	char* xmlHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
	char* topTag_s = "<DeviceCollection>\n";
	char* topTag_e = "</DeviceCollection>\n";

	char* singleTag_s = "<Device>\n";
	char* singleTag_e = "</Device>\n";

	char ipTag_s[] = "<ip-address>";
	char ipTag_e[] = "</ip-address>\n";

	char macTag_s[] = "<mac-address>";
	char macTag_e[] = "</mac-address>\n";

	char subnetmaskTag_s[] = "<subnetmask>";
	char subnetmaskTag_e[] = "</subnetmask>\n";

	char gatewayTag_s[] = "<defaultGateway>";
	char gatewayTag_e[] = "</defaultGateway>\n";

	char deviceVendorTag_s[] = "<deviceVendorValue>";
	char deviceVendorTag_e[] = "</deviceVendorValue>\n";

	char nameOfStationTag_s[] = "<nameOfStation>";
	char nameOfStationTag_e[] = "</nameOfStation>\n";

	char vendorIdTag_s[] = "<vendorId>";
	char vendorIdTag_e[] = "</vendorId>\n";

	char deviceIdTag_s[] = "<deviceId>";
	char deviceIdTag_e[] = "</deviceId>\n";

	char deviceRoleTag_s[] = "<deviceRole>";
	char deviceRoleTag_e[] = "</deviceRole>\n";

	char versionTag_s[] = "<softwareVersion>";
	char versionTag_e[] = "</softwareVersion>\n";

	char orderIdTag_s[] = "<orderId>";
	char orderIdTag_e[] = "</orderId>\n";

	char deviceTypeTag_s[] = "<deviceType>";
	char deviceTypeTag_e[] = "</deviceType>\n";

	char hardwareRevision_s[] = "<HardwareRevision>";
	char hardwareRevision_e[] = "</HardwareRevision>\n";

	char udpPort_s[] = "<UDP_Port>";
	char udpPort_e[] = "</UDP_Port>\n";


	char slots_s[] = "<Slots>\n";
	char slots_e[] = "</Slots>\n";

	char slot_s[] = "<Slot>\n";
	char slot_e[] = "</Slot>\n";

	char subslots_s[] = "<Subslots>\n";
	char subslots_e[] = "</Subslots>\n";

	char subslot_s[] = "<Subslot>\n";
	char subslot_e[] = "</Subslot>\n";

	char slotnumber_s[] = "<slotNumber>";
	char slotnumber_e[] = "</slotNumber>\n";

	char moduelIdentnumber_s[] = "<moduleIdentificationNumber>";
	char moduelIdentnumber_e[] = "</moduleIdentificationNumber>\n";

	char numofsubmodule_s[] = "<numberOfSubmodules>";
	char numofsubmodule_e[] = "</numberOfSubmodules>\n";

	char subslotNumber_s[] = "<subslotNumber>";
	char subslotNumber_e[] = "</subslotNumber>\n";

	char submoduleIdentNumber_s[] = "<submoduleIndetificationNumber>";
	char submoduleIdentNumber_e[] = "</submoduleIndetificationNumber>\n";

	char peerChassisID_s[] = "<peerChassisId>";
	char peerChassisID_e[] = "</peerChassisId>\n";

	char peerMac_s[] = "<peerMACAddress>";
	char peerMac_e[] = "</peerMACAddress>\n";

	char numberOfSubslots_s[] = "<numberOfSubslots>";
	char numberOfSubslots_e[] = "</numberOfSubslots>";

	char numberOfSlots_s[] = "<numberOfSlots>";
	char numberOfSlots_e[] = "</numberOfSlots>";

	// check if file exists
	exists = FileExists(filename);




	// write xml header if file was just now created
	if (!exists){
		err = fopen_s(&fp, filename, "a+");
		if (err != 0){
			printf("Error opening file!\n");
			return -1;
		}
		if (fp == NULL)
		{
			printf("Error filepointer is NULL");
			return -1;
		}
		fprintf_s(fp, "%s", xmlHeader);
		fprintf_s(fp, "%s", topTag_s);
	}
	else{
		err = fopen_s(&fp, filename, "r+");
		if (err != 0 && fp != NULL){
			printf("Error opening file!\n");
			return -1;
		}
		if (fp == NULL)
		{
			printf("Error filepointer is NULL");
			return -1;
		}
		// delete the last line or start writing in the line before
		// get the size of the last tag away from the end of file
		int setposworked = fsetpos(fp, &endpos);

	}



	// write tags 
	fprintf_s(fp, "%s", singleTag_s); // one device == one single tag
	// store ip address
	fprintf_s(fp, "%s%d.%d.%d.%d%s",
		ipTag_s,
		deviceInfo->deviceIp.byte1,
		deviceInfo->deviceIp.byte2,
		deviceInfo->deviceIp.byte3,
		deviceInfo->deviceIp.byte4,
		ipTag_e);

	// store mac address
	fprintf_s(fp, "%s%02x:%02x:%02x:%02x:%02x:%02x%s",
		macTag_s,
		deviceInfo->deviceMACaddress.byte1 & 0xFF,
		deviceInfo->deviceMACaddress.byte2 & 0xFF,
		deviceInfo->deviceMACaddress.byte3 & 0xFF,
		deviceInfo->deviceMACaddress.byte4 & 0xFF,
		deviceInfo->deviceMACaddress.byte5 & 0xFF,
		deviceInfo->deviceMACaddress.byte6 & 0xFF,
		macTag_e);

	// store subnetmask
	//if subnetmask is 205.205.205.205 then the device didn't answer to the pdreal data call
	if (deviceInfo->subnetmask.byte1 == 0xcd &&
		deviceInfo->subnetmask.byte2 == 0xcd &&
		deviceInfo->subnetmask.byte3 == 0xcd &&
		deviceInfo->subnetmask.byte4 == 0xcd)
	{
		// add emtpy tag
		fprintf_s(fp, "%s%s",
			subnetmaskTag_s,
			subnetmaskTag_e);
	}
	else{
		fprintf_s(fp, "%s%d.%d.%d.%d%s",
			subnetmaskTag_s,
			deviceInfo->subnetmask.byte1,
			deviceInfo->subnetmask.byte2,
			deviceInfo->subnetmask.byte3,
			deviceInfo->subnetmask.byte4,
			subnetmaskTag_e);
	}
	// store default gateway
	if (deviceInfo->defaultGateway.byte1 == 0xcd &&
		deviceInfo->defaultGateway.byte2 == 0xcd &&
		deviceInfo->defaultGateway.byte3 == 0xcd &&
		deviceInfo->defaultGateway.byte4 == 0xcd)
	{
		fprintf_s(fp, "%s%s",
			gatewayTag_s,
			gatewayTag_e);
	}
	else
	{
		fprintf_s(fp, "%s%d.%d.%d.%d%s",
			gatewayTag_s,
			deviceInfo->defaultGateway.byte1,
			deviceInfo->defaultGateway.byte2,
			deviceInfo->defaultGateway.byte3,
			deviceInfo->defaultGateway.byte4,
			gatewayTag_e);
	}
	// store Vendor ID
	fprintf_s(fp, "%s0x%04x%s",
		vendorIdTag_s,
		deviceInfo->vendorId,
		vendorIdTag_e);
	// store device Id
	fprintf_s(fp, "%s0x%04x%s",
		deviceIdTag_s,
		deviceInfo->deviceId,
		deviceIdTag_e);
	if (deviceInfo->deviceRoleDetail != 0x00){	// store device role
		fprintf_s(fp, "%s0x%02x%s",
			deviceRoleTag_s,
			deviceInfo->deviceRoleDetail,
			deviceRoleTag_e);
	}
	if (deviceInfo->deviceVendor != NULL){
		// store device vendor
		fprintf_s(fp, "%s%s%s",
			deviceVendorTag_s,
			deviceInfo->deviceVendor,
			deviceVendorTag_e);
	}

	// store name of station
	if (!deviceInfo->nameOfStation){
		fprintf_s(fp, "%s%s",
			nameOfStationTag_s,
			nameOfStationTag_e);
	}
	else{
		fprintf_s(fp, "%s%s%s",
			nameOfStationTag_s,
			deviceInfo->nameOfStation,
			nameOfStationTag_e);
	}
	// store version
	fprintf_s(fp, "%s%s%s",
		versionTag_s,
		deviceInfo->version,
		versionTag_e);
	// store hardware revision
	fprintf_s(fp, "%s%s%s",
		hardwareRevision_s,
		deviceInfo->hardwareRevison,
		hardwareRevision_e);
	// store device Type
	fprintf_s(fp, "%s%s%s",
		deviceTypeTag_s,
		deviceInfo->deviceType,
		deviceTypeTag_e);
	// store order Id
	fprintf_s(fp, "%s%s%s",
		orderIdTag_s,
		deviceInfo->orderId,
		orderIdTag_e);
	fprintf_s(fp, "%s0x%x%s",
		udpPort_s,
		deviceInfo->udpPort,
		udpPort_e);

	// print slots
	if (deviceInfo->slotList){
		fprintf_s(fp, "%s",
			slots_s);
		fprintf_s(fp, "%s%d%s",
			numberOfSlots_s,
			deviceInfo->numberOfSlots,
			numberOfSlots_e);
		linkedList_slot* slots = deviceInfo->slotList;


		while (slots)
		{
			// store the slot 
			fprintf_s(fp, "%s", slot_s);

			// store slotnumber
			fprintf_s(fp, "%s0x%04x%s",
				slotnumber_s,
				slots->slotNumber,
				slotnumber_e);

			// store module indetification number
			fprintf_s(fp, "%s0x%02x%02x%02x%02x%s",
				moduelIdentnumber_s,
				slots->moduleIdentNumber[0] & 0xFF,
				slots->moduleIdentNumber[1] & 0xFF,
				slots->moduleIdentNumber[2] & 0xFF,
				slots->moduleIdentNumber[3] & 0xFF,
				moduelIdentnumber_e);

			// store number of submodules
			fprintf_s(fp, "%s%d%s",
				numberOfSubslots_s,
				slots->numberOfSubmodules,
				numberOfSubslots_e);
			

			// iterate through list of subslots
			linkedList_subslot* subslots = slots->subslotList;
			if (subslots)
			{
				// subslot tag
				fprintf_s(fp, "%s", subslots_s);

				while (subslots)
				{
					fprintf_s(fp, "%s", subslot_s);

					// store subslotnumber
					fprintf_s(fp, "%s0x%04x%s",
						subslotNumber_s,
						subslots->subslotNumber,
						subslotNumber_e);

					// store module indentification number
					fprintf_s(fp, "%s0x%02x%02x%02x%02x%s",
						submoduleIdentNumber_s,
						subslots->submoduleIdentNumber[0] & 0xFF,
						subslots->submoduleIdentNumber[1] & 0xFF,
						subslots->submoduleIdentNumber[2] & 0xFF,
						subslots->submoduleIdentNumber[3] & 0xFF,
						submoduleIdentNumber_e);

					if (subslots->peerChassisID && subslots->peerMacAddress)
					{
						fprintf_s(fp, "%s%s%s",
							peerChassisID_s,
							subslots->peerChassisID,
							peerChassisID_e);

						fprintf_s(fp, "%s%02x:%02x:%02x:%02x:%02x:%02x%s",
							peerMac_s,
							subslots->peerMacAddress->byte1 & 0xFF,
							subslots->peerMacAddress->byte2 & 0xFF,
							subslots->peerMacAddress->byte3 & 0xFF,
							subslots->peerMacAddress->byte4 & 0xFF,
							subslots->peerMacAddress->byte5 & 0xFF,
							subslots->peerMacAddress->byte6 & 0xFF,
							peerMac_e);

					}


					fprintf_s(fp, "%s", subslot_e);
					subslots = subslots->next;
				}



				fprintf_s(fp, "%s", subslots_e);
			}


			fprintf_s(fp, "%s", slot_e);
			slots = slots->next;
		}






		fprintf_s(fp, "%s",
			slots_e);
	}


	// add last tag, device is now writtten
	fprintf_s(fp, "%s", singleTag_e);


	fgetpos(fp, &endpos);
	// file didn't exist before, add endtag
	fprintf_s(fp, "%s", topTag_e);

	fclose(fp);

	return 0;
}

bool FileExists(const char *fname){
	FILE *file;
	errno_t err;
	err = fopen_s(&file, fname, "r");


	if (!err && file!=NULL)
	{
		fclose(file);
		return true;
	}
	return false;
}

