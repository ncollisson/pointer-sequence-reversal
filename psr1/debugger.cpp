#include "stdafx.h"
#include "debugger.h"
#include <iostream>


Debugger::Debugger()
{
}


Debugger::~Debugger()
{
}

int Debugger::SetTargetPID(DWORD target_pid)
{
	this->target_pid = target_pid;
	return 1;
}

int Debugger::SetTargetAddress(LPVOID target_address)
{
	this->target_address = target_address;
	return 1;
}

int Debugger::Attach()
{
	if (!DebugActiveProcess(target_pid))
	{
		std::cout << "Error in DebugActiveProcess(): " << GetLastError() << std::endl;
		return 0;
	}

	if (!DebugSetProcessKillOnExit(FALSE))
	{
		std::cout << "Could not DebugSetProcessKillOnExit(FALSE)" << std::endl;
	}

	std::cout << "Now debugging the target process" << std::endl;

	return 1;
}

int Debugger::SetMemoryBreakpoint(LPVOID target_address)
{
	DWORD old_protect, orig_protect;
	MEMORY_BASIC_INFORMATION page_info;
	PMEMORY_BASIC_INFORMATION ppage_info = &page_info;
	size_t breakpoint_size = 1;

	target_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);

	if (!target_handle)
	{
		std::cout << "Error in OpenProcess(): " << GetLastError() << std::endl;
		return 0;
	}

	std::cout << "Obtained handle to target process" << std::endl;

	if (!VirtualQueryEx(target_handle, target_address, ppage_info, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		std::cout << "Error in VirtualQueryEx(): " << GetLastError() << std::endl;
		return 0;
	}

	orig_protect = ppage_info->Protect;

	if (!VirtualProtectEx(target_handle, target_address, breakpoint_size, orig_protect | PAGE_GUARD, &old_protect))
	{
		std::cout << "Error in VirtualProtectEx(): " << GetLastError() << std::endl;
		return 0;
	}

	std::cout << "Set memory breakpoint, waiting for debug event" << std::endl;

	return 1;
}

int Debugger::WaitForMemoryBreakpoint()
{
	EXCEPTION_RECORD exception_record;
	DEBUG_EVENT debug_event;
	LPDEBUG_EVENT lpdebug_event = &debug_event;
	BOOL breakpoint_hit = FALSE;

	while (!breakpoint_hit)
	{
		if (!WaitForDebugEvent(lpdebug_event, INFINITE))
		{
			std::cout << "Error in WaitForDebugEvent(): " << GetLastError() << std::endl;
			return 0;
		}

		exception_record = lpdebug_event->u.Exception.ExceptionRecord;
		unsigned int i, num = exception_record.NumberParameters;

		switch (lpdebug_event->dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:

			switch (exception_record.ExceptionCode)
			{
			case STATUS_GUARD_PAGE_VIOLATION:
				std::cout << "STATUS_GUARD_PAGE_VIOLATION: Memory breakpoint hit" << std::endl;

				for (i = 0; i < num; i++)
				{
					std::cout << "ExceptionInformation[" << i << "]: " << std::hex << exception_record.ExceptionInformation[i] << std::endl;
				}

				breakpoint_hit = TRUE;

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

	return 1;
}
