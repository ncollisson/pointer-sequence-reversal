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

int Debugger::SetMemoryBreakpoint(LPVOID target_address = NULL)
{
	DWORD old_protect, orig_protect;
	MEMORY_BASIC_INFORMATION page_info;
	PMEMORY_BASIC_INFORMATION ppage_info = &page_info;
	size_t breakpoint_size = 1;

	if (target_handle == NULL)
	{
		target_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);

		if (!target_handle)
		{
			std::cout << "Error in OpenProcess(): " << GetLastError() << std::endl;
			return 0;
		}

		std::cout << "Obtained handle to target process" << std::endl;
	}

	if (target_address == NULL)
	{
		target_address = this->target_address;

		if (target_address == NULL)
		{
			std::cout << "Won't attempt to set breakpoint at NULL address" << std::endl;
			return 0;
		}
	}

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

	while (TRUE)
	{
		if (!WaitForDebugEvent(lpdebug_event, INFINITE))
		{
			std::cout << "Error in WaitForDebugEvent(): " << GetLastError() << std::endl;
			return 0;
		}

		exception_record = lpdebug_event->u.Exception.ExceptionRecord;

		switch (lpdebug_event->dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:

			switch (exception_record.ExceptionCode)
			{
			case STATUS_GUARD_PAGE_VIOLATION:
				// rename this to BreakpointHit(debug_event)
				HandleStatusGuardPageViolation(debug_event, breakpoint_hit);

				if (breakpoint_hit) return 1;

				// The trap flag (single-step breakpoint) must be set
				// before telling program to continue, otherwise the program
				// might execute past the instruction that accesses the desired
				// memory address before the debugger can reset the memory breakpoint

				SetTrapFlag(debug_event);
				break;

			case EXCEPTION_SINGLE_STEP:
				std::cout << "EXCEPTION_SINGLE_STEP code reached" << std::endl;
				SetMemoryBreakpoint(target_address);
				break;

			default:
				std::cout << "EXCEPTION_DEBUG_EVENT other than STATUS_GUARD_PAGE_VIOLATION" << std::endl;
				break;
			}
			break;

		default:
			std::cout << "DEBUG_EVENT other than EXCEPTION_DEBUG_EVENT" << std::endl;
			break;
		}

		ContinueDebugEvent(lpdebug_event->dwProcessId, lpdebug_event->dwThreadId, DBG_CONTINUE);
	}
}

int Debugger::HandleStatusGuardPageViolation(const DEBUG_EVENT& debug_event, BOOL& breakpoint_hit)
{
	LPVOID access_address;
	CONTEXT thread_context;
	LPCONTEXT lpthread_context = &thread_context;
	EXCEPTION_RECORD exception_record = debug_event.u.Exception.ExceptionRecord;
	unsigned int i, num = exception_record.NumberParameters;

	std::cout << "STATUS_GUARD_PAGE_VIOLATION: Page guard hit" << std::endl;

	for (i = 0; i < num; i++)
	{
		std::cout << "ExceptionInformation[" << i << "]: " << std::hex << exception_record.ExceptionInformation[i] << std::endl;
	}

	// ExceptionInformation structure undefined for STATUS_GUARD_PAGE_VIOLATION
	// Consider using PAGE_NOACCESS instead of PAGE_GUARD since
	// ExceptionInformation for EXCEPTION_ACCESS_VIOLATION is defined.

	access_address = (num > 0 ? (LPVOID) exception_record.ExceptionInformation[num - 1] : NULL);

	if (access_address == target_address)
	{
		std::cout << "Memory breakpoint hit" << std::endl;
		breakpoint_hit = TRUE;
	}

	return 1;
}

int Debugger::SetSoftBreakpoint(LPVOID target_address)
{
	char orig_instruction_byte;
	LPVOID lporig_instruction_byte = &orig_instruction_byte;
	char int3 = '\xCC';
	LPCVOID lpcint3 = &int3;

	if (!ReadProcessMemory(target_handle, target_address, lporig_instruction_byte, 1, NULL))
	{
		std::cout << "Error in ReadProcessMemory(): " << GetLastError() << std::endl;
		return 0;
	}

	soft_breakpoint_list[target_address] = orig_instruction_byte;

	if (!WriteProcessMemory(target_handle, target_address, lpcint3, 1, NULL))
	{
		std::cout << "Error in WriteProcessMemory(): " << GetLastError() << std::endl;
		return 0;
	}

	return 1;
}

LPVOID Debugger::GetInstructionPointer(const DEBUG_EVENT& debug_event)
{
	HANDLE thread_handle;
	CONTEXT thread_context;
	LPCONTEXT lpthread_context = &thread_context;
	LPVOID instruction_pointer;;

	thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, debug_event.dwThreadId);

	if (!thread_handle)
	{
		std::cout << "Error in OpenThread(): " << GetLastError() << std::endl;
		return 0;
	}

	thread_context.ContextFlags = CONTEXT_ALL;

	if (!GetThreadContext(thread_handle, lpthread_context))
	{
		std::cout << "Error in GetThreadContext(): " << GetLastError() << std::endl;
		return 0;
	}

	// x86 specific
	instruction_pointer = (LPVOID) lpthread_context->Eip;

	return instruction_pointer;
}

int Debugger::SetTrapFlag(const DEBUG_EVENT& debug_event)
{
	HANDLE thread_handle;
	CONTEXT thread_context;
	LPCONTEXT lpthread_context = &thread_context;

	thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, debug_event.dwThreadId);

	if (!thread_handle)
	{
		std::cout << "Error in OpenThread(): " << GetLastError() << std::endl;
		return 0;
	}

	thread_context.ContextFlags = CONTEXT_CONTROL;

	if (!GetThreadContext(thread_handle, lpthread_context))
	{
		std::cout << "Error in GetThreadContext(): " << GetLastError() << std::endl;
		return 0;
	}

	// x86 specific?
	thread_context.EFlags |= 0x100;

	if (!SetThreadContext(thread_handle, lpthread_context))
	{
		std::cout << "Error in SetThreadContext(): " << GetLastError() << std::endl;
	}

	return 1;
}