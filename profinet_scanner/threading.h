#include "pcap.h"
// headerfile for necessary functions for multithreading

extern DWORD WINAPI sniffer_thread(LPVOID lpParameter);
extern DWORD WINAPI sniffer_thread_DCP(LPVOID lpParameter);
extern DWORD WINAPI sniffer_thread_IP(LPVOID lpParameter);
extern DWORD WINAPI loopTimerThread(LPVOID lpParameter);


extern BOOL LoadNpcapDlls();

