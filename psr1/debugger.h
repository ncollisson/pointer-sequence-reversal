#pragma once
#include <Windows.h>
#include <map>

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
	int SetSoftBreakpoint(LPVOID target_address);

private:
	DWORD target_pid;
	LPVOID target_address;
	HANDLE target_handle = NULL;
	std::map<LPVOID, char> soft_breakpoint_list;

	int HandleStatusGuardPageViolation(const DEBUG_EVENT& debug_event, BOOL& breakpoint_hit);

	LPVOID GetInstructionPointer(const DEBUG_EVENT& debug_event);
	int Debugger::SetTrapFlag(const DEBUG_EVENT& debug_event);
};

