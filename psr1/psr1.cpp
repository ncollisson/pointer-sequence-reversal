#include "stdafx.h"
#include <iostream>
#include <Windows.h>

void DebugLoop(const LPDEBUG_EVENT);

int main()
{
	DWORD target_pid;
	HANDLE target_handle;
	LPVOID target_address;
	DWORD old_protect;
	DEBUG_EVENT debug_event;
	LPDEBUG_EVENT lpdebug_event = &debug_event;

	std::cout << "Enter PID of target process: " << std::endl;
	std::cin >> target_pid;

	target_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);

	if (!target_handle)
	{
		std::cout << "Error in OpenProcess(): " << GetLastError() << std::endl;
		std::cin;
	}

	std::cout << "Obtained handle to target process" << std::endl;

	if (!DebugActiveProcess(target_pid))
	{
		std::cout << "Error in DebugActiveProcess(): " << GetLastError() << std::endl;
		std::cin;
	}

	std::cout << "Now debugging the target process" << std::endl;

	std::cout << "Enter address of interest in hexadecimal (without 0x): " << std::endl;
	std::cin >> std::hex >> target_address;

	if (!VirtualProtectEx(target_handle, target_address, 1, PAGE_READWRITE | PAGE_GUARD, &old_protect))
	{
		std::cout << "Error in VirtualProtectEx(): " << GetLastError() << std::endl;
		std::cin;
	}

	std::cout << "Set memory breakpoint, waiting for debug event" << std::endl;

	DebugLoop(lpdebug_event);

	std::cin;

    return 0;
}

void DebugLoop(const LPDEBUG_EVENT lpdebug_event)
{
	for (;;)
	{
		WaitForDebugEvent(lpdebug_event, INFINITE);

		switch (lpdebug_event->dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:

			switch (lpdebug_event->u.Exception.ExceptionRecord.ExceptionCode)
			{
			case STATUS_GUARD_PAGE_VIOLATION:
				std::cout << "STATUS_GUARD_PAGE_VIOLATION: Memory breakpoint hit" << std::endl;
				break;

			default:
				std::cout << "EXCEPTION_DEBUG_EVENT other than STATUS_GUARD_PAGE_VIOLATION" << std::endl;
				break;
			}
			break;

		default:
			std::cout << "DEBUG_EVENT other than EXCEPTION_DEBUG_EVENT" << std::endl;
		}

		ContinueDebugEvent(lpdebug_event->dwProcessId, lpdebug_event->dwThreadId, DBG_CONTINUE);
	}
}
