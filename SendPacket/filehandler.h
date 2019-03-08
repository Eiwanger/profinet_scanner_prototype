#include "stdafx.h"

#ifndef FILEHANDLER_H
#define FILEHANDLER_H

extern int writeToFile(datasheet* deviceInfo, char* cFilename, mac_address* defaultGatewayMAC);
extern bool FileExists(const char *fname);

// postition of the curser bevor the last tag
fpos_t endpos;

enum portState{
	Up = 0x0001,
	Down = 0x0002,
};

enum deviceRole{
	PNIO_Device = 0x01,
	PNIO_Controller = 0x02,
	PNIO_Multidevice = 0x03,
	PNIO_Supervisor = 0x04,

};

enum MAUType{
	_10BaseT = 0x0005,
	_10BaseTXHD = 0x000A,
	_10BaseTXFD,
	_10BaseFLHD,
	_10BaseFLFD,
	_100BaseTXHD = 0x000F,
	_100BaseTXFD = 0x0010, // Default (MediaType Copper)
	_100BaseFXHD = 0x0011,
	_100BaseFXFD = 0x0012, // Default (MediaType Fiber optic)
	_1000BaseXHD = 0x0015,
	_1000BaseXFD = 0x0016,
	_1000BaseLXHD = 0x0017,
	_1000BaseLXFD = 0x0018,
	_1000BaseSXHD = 0x0019,
	_1000BaseSXFD = 0x001A,
	_1000BaseTHD = 0x001D,
	_1000BaseTFD = 0x001E,
	_10GbaseX = 0x001F,
	_10GbaseLX4 = 0x0020,
	_10GbaseR = 0x0021,
	_10GbaseER = 0x0022,
	_10GbaseLR = 0x0023,
	_10GbaseSR = 0x0024,
	_10GbaseW = 0x0025,
	_10GbaseEW = 0x0026,
	_10GbaseLW = 0x0027,
	_10GbaseSW = 0x0028,
	_10GbaseCX4 = 0x0029,
	_2BaseTL = 0x002A,
	_10PassTS = 0x002B,
	_100BaseBX10D = 0x002C,
	_100BaseBX10U = 0x002D,
	_100BaseLX10 = 0x002E,
	_1000BaseBX10D = 0x002F,
	_1000BaseBX10U = 0x0030,
	_1000BaseLX10 = 0x0031,
	_1000BasePX10D = 0x0032,
	_1000BasePX10U = 0x0033,
	_1000BasePX20D = 0x0034,
	_1000BasePX20U = 0x0035,
	_10GbaseT = 0x0036,   // 10GbaseT or 100BasePXFD
	_10GbaseLRM = 0x0037,
	_1000BaseKX = 0x0038,
	_1000BaseKX4 = 0x0039,
	_1000BaseKR = 0x003A,
	_10G1GbasePRXD1 = 0x003B,
	_10G1GbasePRXD2 = 0x003C,
	_10G1GbasePRXD3 = 0x003D,
	_10G1GbasePRXU1 = 0x003E,
	_10G1GbasePRXU2 = 0x003F,
	_10G1GbasePRXU3 = 0x0040,
	_10GbasePRD1 = 0x0041,
	_10GbasePRD2 = 0x0042,
	_10GbasePRD3 = 0x0043,
	_10GbasePRU1 = 0x0044,
	_10GbasePRU3 = 0x0045,
	_40GbaseKR4 = 0x0046,
	_40GbaseCR4 = 0x0047,
	_40GbaseSR4 = 0x0048,
	_40GbaseFR = 0x0049,
	_40GbaseLR4 = 0x004A,
	_100GbaseCR10 = 0x004B,
	_100GbaseSR10 = 0x004C,
	_100GbaseLR4 = 0x004D,
	_100GbaseER4 = 0x004E,
	_POF = 0x0100,

};
extern char* decodeMAUType(u_short mautype);
extern char* decodeDeviceRole(u_char deviceRole);
extern char* decodePortState(u_short portstate);
extern char* decodeVendorID(u_short vID);
#endif