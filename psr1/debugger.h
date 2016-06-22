#pragma once
#include <Windows.h>

class Debugger
{
public:
	Debugger();
	~Debugger();

	int SetTargetPID(DWORD target_pid);
	int SetTargetAddress(LPVOID target_address);
	int Attach();
	int SetMemoryBreakpoint(LPVOID target_address);
	int WaitForMemoryBreakpoint();

private:
	DWORD target_pid;
	LPVOID target_address;
	HANDLE target_handle;
};

