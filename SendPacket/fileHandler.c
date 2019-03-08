#include "stdafx.h"
#include "filehandler.h"

// writes a give device to a file
// @param deviceInfo -> device with all information
// @param cFilename -> string with path and filename
// @param defGatewayMAC, -> the MAC address of the default gateway to compare during layer 3 scans
int writeToFile(datasheet* deviceInfo, char* cFilename, mac_address* defGatewayMAC)
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


	// tags for xml format 
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

	//	char deviceVendorTag_s[] = "<deviceVendorValue>";
	//	char deviceVendorTag_e[] = "</deviceVendorValue>\n";

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


	char modules_s[] = "<Modules>\n";
	char modules_e[] = "</Modules>\n";

	char module_s[] = "<Module>\n";
	char module_e[] = "</Module>\n";

	char submodules_s[] = "<Submodules>\n";
	char submodules_e[] = "</Submodules>\n";

	char submodule_s[] = "<Submodule>\n";
	char submodule_e[] = "</Submodule>\n";

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
	char numberOfSubslots_e[] = "</numberOfSubslots>\n";

	char numberOfSlots_s[] = "<numberOfSlots>";
	char numberOfSlots_e[] = "</numberOfSlots>\n";

	char ownPortId_s[] = "<ownPortID>";
	char ownPortId_e[] = "</ownPortID>\n";

	char peerPortId_s[] = "<peerPortID>";
	char peerPortId_e[] = "</peerPortID>\n";

	char MAUType_s[] = "<MAUType>";
	char MAUType_e[] = "</MAUType>\n";

	char IMserialNumber_s[] = "<IMserialNumber>";
	char IMserialNumber_e[] = "</IMserialNumber>\n";

	char IMprofilID_s[] = "<IMprofilID>";
	char IMprofilID_e[] = "</IMprofilID>\n";

	char IMprofilSpecificType_s[] = "<IMprofilSpecificType>";
	char IMprofilSpecificType_e[] = "</IMprofilSpecificType>\n";

	char IMversion_s[] = "<IMversion>";
	char IMversion_e[] = "</IMversion>\n";

	char IMsupported_s[] = "<IMsupported>";
	char IMsupported_e[] = "</IMsupported>\n";

	char portstate_s[] = "<portstate>";
	char portstate_e[] = "</portstate>\n";


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
	if (compareMacAddress(deviceInfo->deviceMACaddress, *defGatewayMAC)){
		fprintf_s(fp, "%s%s",
			macTag_s,
			macTag_e);
	}
	else{
		fprintf_s(fp, "%s%02x:%02x:%02x:%02x:%02x:%02x%s",
			macTag_s,
			deviceInfo->deviceMACaddress.byte1 & 0xFF,
			deviceInfo->deviceMACaddress.byte2 & 0xFF,
			deviceInfo->deviceMACaddress.byte3 & 0xFF,
			deviceInfo->deviceMACaddress.byte4 & 0xFF,
			deviceInfo->deviceMACaddress.byte5 & 0xFF,
			deviceInfo->deviceMACaddress.byte6 & 0xFF,
			macTag_e);
	}
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
	fprintf_s(fp, "%s0x%04x / %s%s",
		vendorIdTag_s,
		deviceInfo->vendorId, decodeVendorID(deviceInfo->vendorId),
		vendorIdTag_e);
	// store device Id
	fprintf_s(fp, "%s0x%04x%s",
		deviceIdTag_s,
		deviceInfo->deviceId,
		deviceIdTag_e);
	if (deviceInfo->deviceRoleDetail != 0x00){	// store device role
		fprintf_s(fp, "%s0x%02x / %s%s",
			deviceRoleTag_s,
			deviceInfo->deviceRoleDetail, decodeDeviceRole(deviceInfo->deviceRoleDetail),
			deviceRoleTag_e);
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
	if (deviceInfo->udpPort == 0x0000){

		fprintf_s(fp, "%s%s",
			udpPort_s,
			udpPort_e);
	}
	else{
		fprintf_s(fp, "%s0x%x / %d%s",
			udpPort_s,
			deviceInfo->udpPort,
			deviceInfo->udpPort,
			udpPort_e);
	}
	// print slots
	if (deviceInfo->slotList){
		fprintf_s(fp, "%s",
			modules_s);
		fprintf_s(fp, "%s%d%s",
			numberOfSlots_s,
			deviceInfo->numberOfSlots,
			numberOfSlots_e);
		linkedList_slot* slots = deviceInfo->slotList;


		while (slots)
		{
			// store the slot 
			fprintf_s(fp, "%s", module_s);

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


			// TODO add module information
			// store vendor id
			if (slots->moduledata.version == NULL && slots->moduledata.IMversion == NULL){
				fprintf_s(fp, "%s%s",
					vendorIdTag_s,
					vendorIdTag_e);

				// store order id
				fprintf_s(fp, "%s%s",
					orderIdTag_s,
					orderIdTag_e);

				// store IMserialnumber
				fprintf_s(fp, "%s%s",
					IMserialNumber_s,
					IMserialNumber_e);


				// store hardwarerevison
				fprintf_s(fp, "%s%s",
					hardwareRevision_s,
					hardwareRevision_e);

				// store version
				fprintf_s(fp, "%s%s",
					versionTag_s,
					versionTag_e);


				// store IMprofileId
				fprintf_s(fp, "%s%s",
					IMprofilID_s,
					IMprofilID_e);

				// store IMProfilspecifictype
				fprintf_s(fp, "%s%s",
					IMprofilSpecificType_s,
					IMprofilSpecificType_e);

				// store IMversion
				fprintf_s(fp, "%s%s",
					IMversion_s,
					IMversion_e);

				// store IMProfilspecifictype
				fprintf_s(fp, "%s%s",
					IMsupported_s,
					IMsupported_e);
			}
			else{
				fprintf_s(fp, "%s0x%04x / %s%s",
					vendorIdTag_s,
					slots->moduledata.vendorID, decodeVendorID(slots->moduledata.vendorID),
					vendorIdTag_e);

				// store order id
				fprintf_s(fp, "%s%s%s",
					orderIdTag_s,
					slots->moduledata.orderID,
					orderIdTag_e);

				// store IMserialnumber
				fprintf_s(fp, "%s%s%s",
					IMserialNumber_s,
					slots->moduledata.IMserialNumber,
					IMserialNumber_e);


				// store hardwarerevison
				fprintf_s(fp, "%s%s%s",
					hardwareRevision_s,
					slots->moduledata.hardwareRevison,
					hardwareRevision_e);

				// store version
				fprintf_s(fp, "%s%s%s",
					versionTag_s,
					slots->moduledata.version,
					versionTag_e);


				// store IMprofileId
				fprintf_s(fp, "%s0x%04x%s",
					IMprofilID_s,
					slots->moduledata.IMProfileID,
					IMprofilID_e);

				// store IMProfilspecifictype
				fprintf_s(fp, "%s0x%04x%s",
					IMprofilSpecificType_s,
					slots->moduledata.IMProfileSpecificType,
					IMprofilSpecificType_e);

				// store IMversion
				fprintf_s(fp, "%s%s%s",
					IMversion_s,
					slots->moduledata.IMversion,
					IMversion_e);

				// store IMProfilspecifictype
				fprintf_s(fp, "%s0x%04x%s",
					IMsupported_s,
					slots->moduledata.IMSupported,
					IMsupported_e);
			}

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
				fprintf_s(fp, "%s", submodules_s);

				while (subslots)
				{
					fprintf_s(fp, "%s", submodule_s);

					// store subslotnumber
					fprintf_s(fp, "%s0x%04x%s",
						subslotNumber_s,
						subslots->subslotNumber,
						subslotNumber_e);

					// store own port id
					if (subslots->ownPortID){
						fprintf_s(fp, "%s%s%s",
							ownPortId_s,
							subslots->ownPortID,
							ownPortId_e);
					}
					else{
						fprintf_s(fp, "%s%s",
							ownPortId_s,
							ownPortId_e);
					}

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
						// peer chassis id
						fprintf_s(fp, "%s%s%s",
							peerChassisID_s,
							subslots->peerChassisID,
							peerChassisID_e);

						// peer port id
						fprintf_s(fp, "%s%s%s",
							peerPortId_s,
							subslots->peerPortID,
							peerPortId_e);


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
					// MAU type
					if (subslots->MAUType != 0xFFFF){
						fprintf_s(fp, "%s0x%04x / %s%s",
							MAUType_s,
							subslots->MAUType, decodeMAUType(subslots->MAUType),
							MAUType_e);
					}
					else{
						fprintf_s(fp, "%s%s",
							MAUType_s,
							MAUType_e);
					}
					if (subslots->portState == 0x0000){
						fprintf_s(fp, "%s%s",
							portstate_s,
							portstate_e);
					}
					else{
						fprintf_s(fp, "%s0x%04x / %s%s",
							portstate_s,
							subslots->portState, decodePortState(subslots->portState),
							portstate_e);
					}


					fprintf_s(fp, "%s", submodule_e);
					subslots = subslots->next;
				}



				fprintf_s(fp, "%s", submodules_e);
			}


			fprintf_s(fp, "%s", module_e);
			slots = slots->next;
		}






		fprintf_s(fp, "%s",
			modules_e);
	}


	// add last tag, device is now written
	fprintf_s(fp, "%s", singleTag_e);


	fgetpos(fp, &endpos);
	// add endtag
	fprintf_s(fp, "%s", topTag_e);

	fclose(fp);

	return 0;
}

// checks if under the given path a file exits
bool FileExists(const char *fname){
	FILE *file;
	errno_t err;
	err = fopen_s(&file, fname, "r");


	if (!err && file != NULL)
	{
		fclose(file);
		return true;
	}
	return false;
}

// compares the given portstate with a enum and returns a string
char* decodePortState(u_short portstate)
{
	switch (portstate)
	{
	case Up: return "Up";
	case Down: return "Down";
	default:
		break;
	}
	return "";
}

// compares the given deviceRole with a enum and returns a string
char* decodeDeviceRole(u_char deviceRole)
{
	switch (deviceRole)
	{
	case PNIO_Device: return "IO-Device";
	case PNIO_Controller: return "IO-Controller";
	case PNIO_Multidevice: return "IO-Device, IO-Controller";
	case PNIO_Supervisor: return "IO-Supervisor";

	default:
		break;
	}
	return "";
}

// compares the given mautype with a enum and returns a string
char* decodeMAUType(u_short mautype)
{
	switch (mautype)
	{
	case _10BaseT: return "10BaseT";
	case _10BaseTXHD: return "10BaseTXHD";
	case _10BaseTXFD: return "10BaseTXFD";
	case _10BaseFLHD: return "10BaseFLHD";
	case _100BaseTXHD: return"100BaseTXHD";
	case _100BaseTXFD: return"100BaseTXFD";
	case _100BaseFXHD: return"100BaseFXHD";
	case _100BaseFXFD: return"100BaseFXFD";
	case _1000BaseXHD: return"1000BaseXHD";
	case _1000BaseXFD: return"1000BaseXFD";
	case _1000BaseLXHD: return"1000BaseLXHD";
	case _1000BaseLXFD: return"1000BaseLXFD";
	case _1000BaseSXHD: return"1000BaseSXHD";
	case _1000BaseSXFD: return"1000BaseSXFD";
	case _1000BaseTHD: return"1000BaseTHD";
	case _1000BaseTFD: return"1000BaseTFD";
	case _10GbaseX: return"10GbaseX";
	case _10GbaseLX4: return"10GbaseLX4";
	case _10GbaseR: return"10GbaseR";
	case _10GbaseER: return"10GbaseER";
	case _10GbaseLR: return"10GbaseLR";
	case _10GbaseSR: return"10GbaseSR";
	case _10GbaseW: return"10GbaseW";
	case _10GbaseEW: return"10GbaseEW";
	case _10GbaseLW: return"10GbaseLW";
	case _10GbaseSW: return"10GbaseSW";
	case _10GbaseCX4: return"10GbaseCX4";
	case _2BaseTL: return"2BaseTL";
	case _10PassTS: return"10PassTS";
	case _100BaseBX10D: return"100BaseBX10D";
	case _100BaseBX10U: return"100BaseBX10U";
	case _100BaseLX10: return"100BaseLX10";
	case _1000BaseBX10D: return"1000BaseBX10D";
	case _1000BaseBX10U: return"1000BaseBX10U";
	case _1000BaseLX10: return"1000BaseLX10";
	case _1000BasePX10D: return"1000BasePX10D";
	case _1000BasePX10U: return"1000BasePX10U";
	case _1000BasePX20D: return"1000BasePX20D";
	case _1000BasePX20U: return"1000BasePX20U";
	case _10GbaseT: return"10GbaseT or 100BasePXFD";
	case _10GbaseLRM: return"10GbaseLRM";
	case _1000BaseKX: return"1000BaseKX";
	case _1000BaseKX4: return"1000BaseKX4";
	case _1000BaseKR: return"1000BaseKR";
	case _10G1GbasePRXD1: return"10G1GbasePRXD1";
	case _10G1GbasePRXD2: return"10G1GbasePRXD2";
	case _10G1GbasePRXD3: return"10G1GbasePRXD3";
	case _10G1GbasePRXU1: return"10G1GbasePRXU1";
	case _10G1GbasePRXU2: return"10G1GbasePRXU2";
	case _10G1GbasePRXU3: return"10G1GbasePRXU3";
	case _10GbasePRD1: return"10GbasePRD1";
	case _10GbasePRD2: return"10GbasePRD2";
	case _10GbasePRD3: return"10GbasePRD3";
	case _10GbasePRU1: return"10GbasePRU1";
	case _10GbasePRU3: return"10GbasePRU3";
	case _40GbaseKR4: return"40GbaseKR4";
	case _40GbaseCR4: return"40GbaseCR4";
	case _40GbaseSR4: return"40GbaseSR4";
	case _40GbaseFR: return"40GbaseFR";
	case _40GbaseLR4: return"40GbaseLR4";
	case _100GbaseCR10: return"100GbaseCR10";
	case _100GbaseSR10: return"100GbaseSR10";
	case _100GbaseLR4: return"100GbaseLR4";
	case _100GbaseER4: return"100GbaseER4";
	case _POF: return"Polymeric optical fiber with 100BaseFXFD";

	default:
		break;
	}

	return "unknown";
}



// source: https://io-link.com/share/Downloads/Vendor_ID_Table.xml
char* decodeVendorID(u_short vID)
{
	switch (vID)
	{
	case 1: return "PEPPERL+FUCHS GmbH";
	case 2: return "Rockwell Automation";
	case 17: return "Endress+Hauser";
	case 26: return "SICK AG";
	case 29: return "M-System Co., Ltd.";
	case 38: return "Rosemount Inc.";
	case 42: return "SIEMENS AG";
	case 87: return "wenglor sensoric GmbH";
	case 120: return "Bürkert Werke GmbH";
	case 127: return "LABOM Mess- und Regeltechnik GmbH";
	case 131: return "SMC Corp.";
	case 176: return "Phoenix Contact GmbH &amp; Co. KG";
	case 234: return "J. Schmalz GmbH";
	case 259: return "Bosch Rexroth AG";
	case 262: return "Lenze Drives GmbH";
	case 271: return "Parker Hannifin";
	case 272: return "Fraba B.V.";
	case 285: return "Wago Kontakttechnik GmbH &amp; Co. KG";
	case 286: return "Hilscher Gesellschaft fuer Systemautomation mbH";
	case 287: return "Bosch Rexroth AG";
	case 288: return "Beckhoff Industrie Elektronik";
	case 292: return "Deutschmann Automation GmbH und Co. KG";
	case 295: return "Molex Incorporated";
	case 297: return "Schneider Electric";
	case 303: return "Murrelektronik GmbH";
	case 308: return "Weidmüller Interface GmbH &amp; Co. KG";
	case 309: return "EUCHNER GmbH + Co. KG";
	case 310: return "ifm electronic gmbh";
	case 317: return "Hans Turck GmbH &amp; Co.KG";
	case 333: return "Festo AG &amp; Co. KG";
	case 334: return "MESCO Engineering GmbH";
	case 335: return "TMG TE GmbH";
	case 338: return "Leuze electronic GmbH + Co. KG";
	case 339: return "TR-Electronic GmbH";
	case 342: return "Contrinex AG Industrial Electronics";
	case 347: return "Sensopart Industriesensorik GmbH";
	case 348: return "HYDAC ELECTRONIC GMBH";
	case 350: return "Baumer Electric AG";
	case 355: return "Comtrol Corporation";
	case 362: return "Belden Deutschland GmbH";
	case 375: return "Karl E. Brinkmann GmbH";
	case 396: return "Renesas Electronics Corporation";
	case 401: return "GEMUE Gebr. Mueller Apparatebau GmbH &amp; Co. KG";
	case 412: return "Datalogic s.r.l";
	case 414: return "embeX GmbH";
	case 418: return "HOMAG AG";
	case 419: return "microsonic GmbH";
	case 422: return "HMT Microelectronic AG";
	case 431: return "Infineon Technologies AG";
	case 451: return "Banner Engineering Corp.";
	case 452: return "Texas Instruments";
	case 478: return "Maxim Integrated Products, Inc.";
	case 505: return "GEFRAN SPA";
	case 507: return "Pentronic AB";
	case 509: return "KEYENCE CORPORATION";
	case 516: return "MESA Systemtechnik GmbH";
	case 528: return "UNIVER S.p.A.";
	case 540: return "MITSUBISHI ELECTRIC CORPORATION";
	case 545: return "di-soric GmbH &amp; Co. KG";
	case 558: return "Freescale Semiconductor";
	case 561: return "ITOH DENKI CO.,LTD";
	case 565: return "CREATIVE CHIPS GmbH";
	case 576: return "IQ2 Development GmbH";
	case 587: return "K. A. Schmersal GmbH &amp; Co. KG";
	case 592: return "iC-Haus GmbH";
	case 604: return "TRsystems GmbH";
	case 612: return "OMRON Corporation";
	case 621: return "Sensirion AG";
	case 623: return "Hosta Motion Control CO.,LTD";
	case 635: return "Wachendorff Automation GmbH &amp; Co.KG";
	case 641: return "LAUMAS ELETTRONICA SRL";
	case 643: return "Friedrich Luetze GmbH";
	case 646: return "TEConcept GmbH";
	case 669: return "BD SENSORS GmbH";
	case 673: return "HSD S.p.A.";
	case 690: return "WERMA Signaltechnik GmbH + Co. KG";
	case 693: return "AVENTICS GmbH";
	case 696: return "E-T-A Elektrotechnische Apparate GmbH";
	case 703: return "EGE-Elektronik Spezial-Sensoren GmbH";
	case 728: return "halstrup-walcher GmbH";
	case 734: return "LARsys-Automation GmbH";
	case 753: return "ASCO Numatics GmbH";
	case 754: return "SONTEC Sensorbau GmbH";
	case 757: return "Anywire Corporation";
	case 763: return "PATLITE Corporation";
	case 765: return "SCHUNK GmbH &amp; Co. KG";
	case 773: return "M.D. Micro Detectors S.p.A.";
	case 779: return "Novotechnik Messwertaufnehmer OHG";
	case 780: return "ipf electronic gmbh";
	case 786: return "Tianjin Geneuo Technology Co., Ltd.";
	case 789: return "XECRO GmbH";
	case 791: return "Germbedded GmbH";
	case 793: return "Bernstein AG";
	case 795: return "Bühler Technologies GmbH";
	case 796: return "PIAB AB";
	case 806: return "RAFI Systec GmbH + Co. KG";
	case 807: return "AMADA ENGINEERING CO., LTD.";
	case 808: return "Lemonage Software GmbH";
	case 809: return "MTS Sensor Technologie GmbH + Co. KG";
	case 810: return "TRONTEQ Electronic GbR";
	case 811: return "Cosys Inc.";
	case 815: return "Weiss Robotics GmbH + Co. KG";
	case 820: return "MLS Lanny GmbH";
	case 821: return "TE Connectivity Germany GmbH";
	case 829: return "Cypress Semiconductor";
	case 832: return "KELLER HCW GmbH";
	case 834: return "Panasonic Industrial Devices SUNX Co., Ltd.";
	case 836: return "Zimmer GmbH";
	case 837: return "autosen gmbh";
	case 839: return "JUMO GmbH u. Co. KG";
	case 844: return "AIRTEC Pneumatic GmbH";
	case 847: return "U.I. Lapp GmbH";
	case 850: return "Genge Thoma AG";
	case 851: return "Sensor Instruments GmbH";
	case 855: return "CKD Corporation";
	case 856: return "MP-SENSOR GmbH";
	case 867: return "CHUO ELECTRONICS CO.,LTD";
	case 871: return "NAGANO KEIKI CO., LTD.";
	case 877: return "Aquaduna GmbH &amp; Co. KG";
	case 888: return "Balluff";
	case 896: return "Carlo Gavazzi Industri A/S";
	case 898: return "Barksdale GmbH";
	case 899: return "Autonics Corporation";
	case 900: return "W.E.St. Elektronik GmbH";
	case 910: return "Azbil Corporation";
	case 911: return "JSL Technology Co.,Ltd";
	case 923: return "Contelec AG";
	case 926: return "K.MECS Co., LTD";
	case 929: return "Takenaka Electronic Industrial Co. Ltd.";
	case 930: return "SICK OPTEX CO., LTD.";
	case 931: return "Bräuer Systemtechnik GmbH";
	case 942: return "Norgren GmbH";
	case 947: return "DUOmetric AG";
	case 949: return "Römheld GmbH Friedrichshütte";
	case 950: return "M&amp;M Software GmbH";
	case 960: return "Layher AG";
	case 961: return "Fraunhofer-Institut für Mikroelektronische Schaltungen und Systeme IMS";
	case 970: return "Advantech Europe BV";
	case 973: return "IVG Göhringer";
	case 974: return "MYOTOKU Ltd.";
	case 979: return "Aichi Tokei Denki co.,Ltd";
	case 980: return "motrona GmbH";
	case 985: return "B&amp;PLUS KK";
	case 986: return "Nabeya Bi-tech Kaisha";
	case 997: return "Utthunga Technologies";
	case 998: return "Kawasaki Heavy Industries, Ltd.";
	case 999: return "Mechatronics Labs S.r.l.";
	case 1000: return "BLOCK Transformatoren-Elektronik GmbH";
	case 1004: return "CONTEC CO., LTD.";
	case 1010: return "FIAtec GmbH";
	case 1011: return "Coretigo Ltd";
	case 1019: return "Delta Electronics, Inc.";
	case 1020: return "MISUMI Corporation";
	case 1021: return "MACOME CORPORATION";
	case 1045: return "Koganei Corporation";
	case 1046: return "Metal Work SpA";
	case 1053: return "Braunkabel GmbH";
	case 1054: return "elobau GmbH &amp; Co. KG";
	case 1055: return "Peter Hirt GmbH";
	case 1057: return "COVAL SAS";
	case 1061: return "STMicroelectronics";
	case 1065: return "ELGO Electronic GmbH &amp; Co. KG";
	case 1066: return "Fuzhou ATK electronic Co.,ltd";
	case 1070: return "KSB SAS";
	case 1073: return "WITTENSTEIN cyber motor GmbH";
	case 1074: return "TAIYO,LTD.";
	case 1075: return "SIKO GmbH";
	case 1076: return "OPTEX FA CO.,LTD.";
	case 1084: return "Hefei Onsoon Intelligent Electronics Co., Ltd.";
	case 1088: return "IBS Japan Co., Ltd.";
	case 1089: return "Kirchgaesser Industrieelektronik GmbH";
	case 1091: return "HYDROTECHNIK GmbH";
	case 1093: return "PULS GmbH";
	case 1094: return "SMW-AUTOBLOK Spannsysteme GmbH";
	case 1095: return "KUNBUS GmbH";
	case 1100: return "scemtec Transponder Technology GmbH";
	case 1105: return "KOBOLD Messring GmbH";
	case 1108: return "FAS Electronics (Fujian).CO.,Ltd.";
	case 1109: return "Dyadic Systems Co.,Ltd.";
	case 1115: return "TAIHEI SYSTEM KOGYO CO., LTD";
	case 1116: return "Shanghai Lanbao Sensing Technology Co.,Ltd";
	case 1117: return "promesstec GmbH";
	case 1127: return "SED Flow Control GmbH";
	case 1128: return "BEI Sensors SAS";
	case 1129: return "RECHNER Industrie-Elektronik GmbH";
	case 1132: return "SHENZHEN SIGNAL ELECTRONICS CO.,LTD";
	case 1137: return "ARROW Central Europe GmbH";
	case 1138: return "Anderson-Negele";
	case 1144: return "Nanotec Electronic GmbH &amp; Co. KG";
	case 1145: return "IDEC CORPORATION";
	case 1152: return "Yamamoto Electric Works Co., Ltd.";
	case 1157: return "KROHNE Messtechnik GmbH";
	case 1161: return "rrumba electronic GmbH";
	case 1166: return "Panasonic Electric Works Europe AG";
	case 1167: return "LINAK A/S";
	case 1171: return "rt-labs AB";
	case 1174: return "WEG INDÚSTRIAS S/A - AUTOMAÇÃO";
	case 1180: return "Seli GmbH Automatisierungstechnik";
	case 1181: return "Elco (Tianjin) Electronics Co., Ltd.";
	case 1182: return "Müller Industrie-Elektronik GmbH";
	case 1184: return "KunShan SVLEC Electrical Co. LTD";
	case 1189: return "WIKA Alexander Wiegand SE &amp; Co. KG";
	case 1191: return "STEM S.r.L.";
	case 1192: return "GIMATIC S.R.L";
	case 1193: return "GICAM S.R.L";
	case 1198: return "Sitomatic Process Technology B.V.";
	case 1206: return "ACS Control System GmbH";
	case 1211: return "ISAC SRL";
	case 1213: return "Metrol Co., Ltd.";
	case 1214: return "Meister Strömungstechnik GmbH";
	case 1215: return "Heidelberger Druckmaschinen AG";
	case 1218: return "Diana Electronic-Systeme GmbH";
	case 1672: return "Intellisense (Xiamen) Microelectronics Ltd";
	case 2351: return "Pilz GmbH &amp; Co. KG";
	case 2403: return "Prozesskommunikation, TU Dresden";
	default: return"";
	}
}