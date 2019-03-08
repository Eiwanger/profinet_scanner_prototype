#include "pcap.h"

#ifndef THREADING_H
#define THREADING_H
// headerfile for necessary functions for multithreading

//extern DWORD WINAPI sniffer_thread(LPVOID lpParameter); // 
extern DWORD WINAPI sniffer_thread_DCP(LPVOID lpParameter); // ->main
extern DWORD WINAPI sniffer_thread_IP(LPVOID lpParameter); // ->main
extern DWORD WINAPI loopTimerThread(LPVOID lpParameter); //-> packet capturer


extern BOOL LoadNpcapDlls();


#endif