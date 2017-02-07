#include "stdafx.h"
#include "debugger.h"
#include <iostream>
#include <tlhelp32.h>
#include <array>
#include "capstone.h"
//#include <stdio.h>
#include <inttypes.h>
#include "CsCapstoneHelper.hh"
#include "Disasm.hpp"
#include "CsIns.hpp"
#include "X86Disasm.hh"
int (WINAPIV * __vsnprintf)(char *, size_t, const char*, va_list) = _vsnprintf;


Debugger::Debugger()
{
	// probably bad
	// Tracer: cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle);

	// also, where to initialize tracer?
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

	//std::cout << "Set memory breakpoint, waiting for debug event" << std::endl;

	return 1;
}

int Debugger::WaitForMemoryBreakpoint()
{
	EXCEPTION_RECORD exception_record;
	DEBUG_EVENT debug_event;
	LPDEBUG_EVENT lpdebug_event = &debug_event;
	DWORD offending_thread_ID;
	HANDLE new_thread_handle;
	DWORD new_thread_id;
	CONTEXT thread_context;
	BOOL wait_to_set_mem_bp = FALSE;
	const size_t MAX_INSTRUCTION_LENGTH = 15;
	uint8_t instruction_buffer[2 * MAX_INSTRUCTION_LENGTH] = {0};
	SIZE_T num_bytes_read;
	size_t cs_count;
	cs_insn *insn;

	// maybe up here set trap flag

	// 0x51 == Q key
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

			offending_thread_ID = lpdebug_event->dwThreadId;

			switch (exception_record.ExceptionCode)
			{
			case STATUS_GUARD_PAGE_VIOLATION:
				if (IsMemoryBreakpointHit(debug_event))
				{
					// analyze run trace recording for that thread
					// how?
					
					// save/print the analysis
					// restart the trace for that thread

					/*
					get offending instruction
						is next instruction atm, currently not captured in trace
						pull max_instruction_length * 2, get second instruction
					analyze it to see which register x was used for the access
						should be the only register in the instruction?
							not necessarily, but good enough for now?
					determine which register y gave register x its value
					find most recent instruction modifying register y
					continue until register obtains value from stack or static memory
						how to identify static memory or stack?
						win api call to get memory regions
					print each instruction that pertains to the access
					*/

					GetCurrentThreadContext(offending_thread_ID, thread_context);

					// profile this and other rpms, how bad are they?
					// probably doesnt matter too much this doesnt happen very often
					ReadProcessMemory(target_handle, LPCVOID (thread_context.Eip), instruction_buffer, sizeof(instruction_buffer), &num_bytes_read);

					cs_count = cs_disasm(Tracer->cs_handle, instruction_buffer, sizeof(instruction_buffer), thread_context.Eip, 0, &insn);

					// do we need to do the first or second insn from buffer?
					// if first, just get rid of 2x max size
					cs_insn offending_instruction = insn[1];
					Tracer->AnalyzeInstructions(offending_instruction);

					/*
					// maybe move cs_handle to class data member?
					//if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle) != CS_ERR_OK) std::cout << "Error in cs_open()" << std::endl;
					cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

					cs_count = cs_disasm(cs_handle, instruction_buffer, sizeof(instruction_buffer), thread_context.Eip, 0, &insn);

					cs_regs regs_read, regs_write;
					uint8_t read_count, write_count;
					std::string register_read_name;

					if (cs_count > 0)
					{
						for (size_t i = 0; i < 1; i++)
						{
							std::cout << std::endl;
							std::cout << "offending instruction:" << std::endl;
							std::cout << "address: " << insn[i].address << "\tmnemonic: " << insn[i].mnemonic << "\t" << insn[i].op_str << std::endl;
							if (insn[i].detail->regs_read_count > 0)
							{
								//std::cout << "\tused for access: " << cs_reg_name(cs_handle, insn[i].detail->regs_read[0]) << std::endl;
							}
							else
							{
								//std::cout << "no regs read" << std::endl;
							}

							if (cs_regs_access(cs_handle, &insn[i],
						        regs_read, &read_count,
								regs_write, &write_count) == 0) {

								// may have to only use read access exceptions for now
								// correctly identifies that ecx is read from in "mov esi, [ecx + 4]"
								// need to check accuracy with other instructions
								// if its not accurate enough, might have to default to just printing
								// full run trace with reg modifications and instructions
								if (read_count > 0 && exception_record.ExceptionInformation[0] == 0) {
									std::cout << "\n\tRegisters read: ";
									for (i = 0; i < read_count; i++) {
										register_read_name = cs_reg_name(cs_handle, regs_read[i]);
										std::cout << register_read_name << " " << std::endl;

										AnalyzeRunTrace(offending_thread_ID, thread_context, regs_read[i], read_count);
									}
									std::cout << "\n";
								}

								// looks like capstone wont identify written registers well
								// wont know that ecx is written in	"mov [ecx + 4], esi"
								if (write_count > 0 && exception_record.ExceptionInformation[0] == 1) {
									std::cout << "\n\tRegisters written: ";
									for (i = 0; i < write_count; i++) {
										std::cout << cs_reg_name(cs_handle, regs_write[i]) << " " << std::endl;
									}
									std::cout << "\n";
								}
							} 
						}
					}

					cs_free(insn, cs_count);
z
					std::cout << "Eip is: " << std::hex << thread_context.Eip << std::endl;

					PrintRunTrace(offending_thread_ID);
					std::cout << "\n\n\n\n";
					*/
					
				}

				SetTrapFlag(offending_thread_ID);
				ContinueDebugEvent(lpdebug_event->dwProcessId, lpdebug_event->dwThreadId, DBG_CONTINUE);

				// wait a little bit before setting the mem bp again so the target program can get 
				// past the instruction that triggered the guard page violation. otherwise the target
				// program gets stuck on the same instruction over and over. should play around with
				// the amount of sleep time for optimal performance
				Sleep(200);
				SetMemoryBreakpoint(target_address);

				continue;

			case EXCEPTION_SINGLE_STEP:

				if (!ReadProcessMemory(target_handle, LPCVOID(thread_context.Eip), instruction_buffer, sizeof(instruction_buffer), &num_bytes_read))
				{
					std::cout << "Error in ReadProcessMemory(): " << GetLastError() << std::endl;
					return 0;
				}

				GetCurrentThreadContext(offending_thread_ID, thread_context);
				Tracer->SaveInstructionInfo(instruction_buffer, max_insn_size, offending_thread_ID, thread_context);

				SetTrapFlag(offending_thread_ID);
				
				break;

			default:
				//std::cout << "EXCEPTION_DEBUG_EVENT other than STATUS_GUARD_PAGE_VIOLATION or single step" << std::endl;
				//std::cout << "debug event code: " << exception_record.ExceptionCode << std::endl;
				break;
			}
			break;

		case CREATE_THREAD_DEBUG_EVENT:
			//std::cout << "create thread debug event" << std::endl;
			new_thread_handle = lpdebug_event->u.CreateProcessInfo.hThread;
			new_thread_id = GetThreadId(new_thread_handle);
			thread_handles.insert_or_assign(new_thread_id, new_thread_handle);
			SetTrapFlag(new_thread_id);

			break;

		default:
			//std::cout << "DEBUG_EVENT other than EXCEPTION_DEBUG_EVENT" << std::endl;
			//std::cout << "debug event code: " << lpdebug_event->dwDebugEventCode << std::endl;
			break;
		}

		ContinueDebugEvent(lpdebug_event->dwProcessId, lpdebug_event->dwThreadId, DBG_CONTINUE);
	}
}

int Debugger::AnalyzeRunTrace(DWORD thread_id, CONTEXT thread_context, uint16_t register_ID, uint8_t read_count)
{
	// get register read from
	// get value in that register
	// iterate through run trace vector to find first occurrence of that value
	// start over, until there isnt a register read from? see if this works

	int value;

	switch (register_ID)
	{
	case 20: // eax
	case 21: // ebx
	case 22: // ecx
	case 23: // edi
	case 24: // edx
	case 25: // esi

	}

	while (read_count > 0)
	{
		//value = thread_context.
	}
}

/*
int Debugger::SaveInstructionInfo(DWORD thread_id, const CONTEXT& thread_context)
{
	// instead of parsing now, lets just save raw code and parse after mem bp has been hit
	// would have to just save max_instruction_length worth of bytes from eip each time
	// then parse later and take insn[0] from each saved chunk
	const unsigned int MAX_INSTRUCTION_LENGTH = 15;
	uint8_t instruction_buffer[MAX_INSTRUCTION_LENGTH] = { 0 };
	SIZE_T num_bytes_read = 0;
	size_t cs_count = 0;
	cs_insn *insn;

	ReadProcessMemory(target_handle, LPCVOID(thread_context.Eip), instruction_buffer, sizeof(instruction_buffer), &num_bytes_read);

	//if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle) != CS_ERR_OK) std::cout << "Error in cs_open()" << std::endl;
	cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_count = cs_disasm(cs_handle, instruction_buffer, sizeof(instruction_buffer), thread_context.Eip, 0, &insn);

	std::tuple<DWORD, cs_insn, std::map<std::string, DWORD>> instruction;
	std::map<std::string, DWORD> modifications;

	if (thread_context.Eip != all_threads_saved_contexts[thread_id].Eip) modifications["Eip"] = thread_context.Eip;
	if (thread_context.Eax != all_threads_saved_contexts[thread_id].Eax) modifications["Eax"] = thread_context.Eax;
	if (thread_context.Ebx != all_threads_saved_contexts[thread_id].Ebx) modifications["Ebx"] = thread_context.Ebx;
	if (thread_context.Ecx != all_threads_saved_contexts[thread_id].Ecx) modifications["Ecx"] = thread_context.Ecx;
	if (thread_context.Edx != all_threads_saved_contexts[thread_id].Edx) modifications["Edx"] = thread_context.Edx;
	if (thread_context.Edi != all_threads_saved_contexts[thread_id].Edi) modifications["Edi"] = thread_context.Edi;
	if (thread_context.Esi != all_threads_saved_contexts[thread_id].Esi) modifications["Esi"] = thread_context.Esi;

	if (cs_count > 0)
	{
		instruction = std::make_tuple(thread_context.Eip, insn[0], modifications);

		if (all_threads_saved_instructions[thread_id].size() >= MAX_TRACE_LENGTH)
		{
			all_threads_saved_instructions[thread_id].erase(all_threads_saved_instructions[thread_id].begin());
		}

		all_threads_saved_instructions[thread_id].push_back(instruction);
	}

	cs_free(insn, cs_count);

	return 1;
}
*/

int Debugger::IsMemoryBreakpointHit(const DEBUG_EVENT& debug_event)
{
	LPVOID access_address;
	EXCEPTION_RECORD exception_record = debug_event.u.Exception.ExceptionRecord;
	unsigned int i, num = exception_record.NumberParameters;
	BOOL mem_breakpoint_hit = FALSE;

	//std::cout << "STATUS_GUARD_PAGE_VIOLATION: Page guard hit" << std::endl;

	for (i = 0; i < num; i++)
	{
		//std::cout << "ExceptionInformation[" << i << "]: " << std::hex << exception_record.ExceptionInformation[i] << std::endl;
	}

	// ExceptionInformation structure undefined for STATUS_GUARD_PAGE_VIOLATION
	// Consider using PAGE_NOACCESS instead of PAGE_GUARD since
	// ExceptionInformation for EXCEPTION_ACCESS_VIOLATION is defined.

	access_address = (num > 0 ? (LPVOID) exception_record.ExceptionInformation[num - 1] : NULL);

	if (access_address == target_address)
	{
		std::cout << "Memory breakpoint hit\n" << std::endl;
		mem_breakpoint_hit = TRUE;
	}

	return mem_breakpoint_hit;
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
	CONTEXT thread_context;
	LPCONTEXT lpthread_context = &thread_context;
	LPVOID instruction_pointer;;

	HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, debug_event.dwThreadId);

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

int Debugger::SetTrapFlag(DWORD thread_id)
{
	HANDLE thread_handle;
	CONTEXT thread_context;

	if (thread_handles.find(thread_id) != thread_handles.end())
	{
		thread_handle = thread_handles[thread_id];
	} 
	else 
	{
		thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);

		if (!thread_handle)
		{
			std::cout << "Error in OpenThread(): " << GetLastError() << std::endl;
			return 0;
		}

		thread_handles.insert_or_assign(thread_id, thread_handle);
	}

	thread_context.ContextFlags = CONTEXT_CONTROL;

	if (!GetThreadContext(thread_handle, &thread_context))
	{
		std::cout << "Error in GetThreadContext(): " << GetLastError() << std::endl;
		return 0;
	}

	// x86 specific
	thread_context.EFlags |= 0x100;

	if (!SetThreadContext(thread_handle, &thread_context))
	{
		std::cout << "Error in SetThreadContext(): " << GetLastError() << std::endl;
	}

	return 1;
}

int Debugger::StartRecordingRegisterModifications()
{
	// get handle for each thread
	// set single step breakpoints on each one

	ListProcessThreads(target_pid);

	for (auto & thread_ID : target_thread_IDs)
	{
		std::cout << "setting trap flag on thread id: " << thread_ID << std::endl;
		if (!SetTrapFlag(thread_ID)) std::cout << "error setting trap flag: " << GetLastError() << std::endl;
	}

	return 1;
}

int Debugger::GetCurrentThreadContext(DWORD thread_id, CONTEXT &thread_context)
{
	// close all these handles
	HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);

	if (!thread_handle)
	{
		std::cout << "Error in OpenThread(): " << GetLastError() << std::endl;
		return 0;
	}

	thread_context.ContextFlags = CONTEXT_ALL;

	if (!GetThreadContext(thread_handle, &thread_context))
	{
		std::cout << "Error in GetThreadContext(): " << GetLastError() << std::endl;
		return 0;
	}

	return 1;
}

int Debugger::SaveRegisterChanges(DWORD thread_id, const CONTEXT &thread_context)
{
	std::map<std::string, DWORD> modifications;

	if (thread_context.Eip != saved_thread_context.Eip) modifications["Eip"] = thread_context.Eip;
	if (thread_context.Eax != saved_thread_context.Eax) modifications["Eax"] = thread_context.Eax;
	if (thread_context.Ebx != saved_thread_context.Ebx) modifications["Ebx"] = thread_context.Ebx;
	if (thread_context.Ecx != saved_thread_context.Ecx) modifications["Ecx"] = thread_context.Ecx;
	if (thread_context.Edx != saved_thread_context.Edx) modifications["Edx"] = thread_context.Edx;
	if (thread_context.Edi != saved_thread_context.Edi) modifications["Edi"] = thread_context.Edi;
	if (thread_context.Esi != saved_thread_context.Esi) modifications["Esi"] = thread_context.Esi;

	if (modifications.size() > 1)
	{
		const unsigned int MAX_RECORD_LENGTH = 50;
		if (all_threads_register_changes[thread_id].size() > MAX_RECORD_LENGTH)
		{
			all_threads_register_changes[thread_id].erase(all_threads_register_changes[thread_id].begin());
		}

		all_threads_register_changes[thread_id].push_back(modifications);
	}

	return 1;
}

int Debugger::PrintRegisterChanges(DWORD thread_id)
{
	DWORD Eip_value;

	std::cout << "trace for thread: " << thread_id << std::endl;

	for (auto &instruction_map : all_threads_register_changes[thread_id])
	{
		Eip_value = instruction_map["Eip"];
		std::cout << "Eip: " << Eip_value << ",  ";

		for (auto &register_modification : instruction_map)
		{
			if (register_modification.first != "Eip")
			{
				std::cout << register_modification.first << ": " << std::hex << register_modification.second << ", ";
			}
		}

		std::cout << std::endl;
	}
	return 1;
}

int Debugger::PrintRunTrace(DWORD thread_id)
{
	DWORD Eip_value;
	cs_insn insn;
	std::map<std::string, DWORD> modifications;

	std::cout << "trace for thread: " << thread_id << std::endl;

	for (auto &instruction_tuple : all_threads_saved_instructions[thread_id])
	{
		std::tie(Eip_value, insn, modifications) = instruction_tuple;

		std::cout << "0x" << std::hex << Eip_value << "\t" << insn.mnemonic << " " << insn.op_str << "\tmods: ";

		for (auto &modification : modifications)
		{
			std::cout << modification.first << " " << std::hex << modification.second << ", ";
		}

		std::cout << "\n\n";
	}

	return 1;
}

// taken from msdn
BOOL Debugger::ListProcessThreads(DWORD dwOwnerPID)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32First(hThreadSnap, &te32))
	{
		std::cout << TEXT("Thread32First") << std::endl;  // Show cause of failure
		CloseHandle(hThreadSnap);     // Must clean up the snapshot object!
		return(FALSE);
	}

	do
	{
		if (te32.th32OwnerProcessID == dwOwnerPID)
		{
			// store thread ID
			target_thread_IDs.push_back(te32.th32ThreadID);
		}
	} while (Thread32Next(hThreadSnap, &te32));

	//  Don't forget to clean up the snapshot object.
	CloseHandle(hThreadSnap);
	return(TRUE);
}