#include "stdafx.h"
#include <Windows.h>
#include <map>
#include <vector>
#include <string>
#include <iostream>
#include <tuple>
#include "Tracer.h"


Tracer::Tracer()
	: cs_handle(NULL) // how to do this right? should we initialize handle to null or an actual handle value here?
{
	InitializeCapstone();
}

int Tracer::InitializeCapstone()
{
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle) != CS_ERR_OK) std::cout << "Error in cs_open()" << std::endl;
	cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
}


Tracer::~Tracer()
{}

int Tracer::SaveInstructionInfo(uint8_t* instruction_buffer, size_t max_insn_size, DWORD thread_id, const CONTEXT& thread_context)
{
	// instead of parsing now, lets just save raw code and parse after mem bp has been hit
	// would have to just save max_instruction_length worth of bytes from eip each time
	// then parse later and take insn[0] from each saved chunk
	SIZE_T num_bytes_read = 0;
	size_t cs_count = 0;
	cs_insn *insnp;
	DWORD previous_eip = 0, 
		  current_eip = thread_context.Eip;

	if (!all_threads_saved_instructions[thread_id].empty())
	{
		// get<0> since eip (i.e., address) for an instruction is first element of instrution tuple
		previous_eip = std::get<0>(all_threads_saved_instructions[thread_id].back());
	}

	cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_count = cs_disasm(cs_handle, instruction_buffer, max_insn_size, thread_context.Eip, 0, &insnp);

	std::tuple<DWORD, cs_insn, std::map<std::string, DWORD>> instruction;
	std::map<std::string, DWORD> modifications;

	//if (thread_context.Eip != all_threads_saved_contexts[thread_id].Eip) modifications["Eip"] = thread_context.Eip;
	if (thread_context.Eax != all_threads_saved_contexts[thread_id].Eax) modifications["Eax"] = thread_context.Eax;
	if (thread_context.Ebx != all_threads_saved_contexts[thread_id].Ebx) modifications["Ebx"] = thread_context.Ebx;
	if (thread_context.Ecx != all_threads_saved_contexts[thread_id].Ecx) modifications["Ecx"] = thread_context.Ecx;
	if (thread_context.Edx != all_threads_saved_contexts[thread_id].Edx) modifications["Edx"] = thread_context.Edx;
	if (thread_context.Edi != all_threads_saved_contexts[thread_id].Edi) modifications["Edi"] = thread_context.Edi;
	if (thread_context.Esi != all_threads_saved_contexts[thread_id].Esi) modifications["Esi"] = thread_context.Esi;

	// check that prev eip and current eip dont match, or else mem bp triggering instructions will get added twice
	if (cs_count > 0 && previous_eip != current_eip)
	{
		instruction = std::make_tuple(thread_context.Eip, insnp[0], modifications);

		if (all_threads_saved_instructions[thread_id].size() >= max_trace_length)
		{
			all_threads_saved_instructions[thread_id].erase(all_threads_saved_instructions[thread_id].begin());
		}

		all_threads_saved_instructions[thread_id].push_back(instruction);
	}

	cs_free(insnp, cs_count);

	return 1;
}

int Tracer::AnalyzeRunTrace(DWORD thread_id, EXCEPTION_RECORD exception_record)
{
	// first, print whole trace
	// then, try to analyze trace based on read/written register in offending insn
	// if analysis is successful/useful, print the analysis

	// probably want to make this more like analyze saved instructions
	// takes no args, just looks at current trace for thread, oh maybe i need to know which thread to do

	cs_regs regs_read, regs_write;
	uint8_t read_count, write_count;
	std::string register_read_name;

	cs_insn insn = std::get<1>(all_threads_saved_instructions[thread_id].back());

	// look at last instruction
	// identify register x used to access address
	cs_regs_access(cs_handle, &insn, regs_read, &read_count, regs_write, &write_count);

	// exceptioninformation[0] == 0 when memory read violation
	if (read_count > 0 && exception_record.ExceptionInformation[0] == 0)
	{
		if (read_count > 1)
		{
			// for now only attempt tracing back from instructions where one register is read from
			// figure out what to do about instructions like "mov eax, [ecx + edx * 4]" later
			// probably want to guess that register with higher value contains useful address
			return 0;
		}

		const char *reg_name;
		bool found = false, analysis_succeeded = false;
		DWORD value;
		uint64_t last_insn_address = 0;

		while (!analysis_succeeded)
		{
			reg_name = cs_reg_name(cs_handle, regs_read[0]);

			value = GetValueOfRegisterForInstruction(thread_id, reg_name, insn, found);
			if (!found) break;

			if (IsStaticAddress(value))
			{
				analysis_succeeded = true;
				break;
			}

			insn = FindEarliestOccurenceOfValueInTrace(value); // returns some instruction 
			if (insn.address == last_insn_address) break;
			last_insn_address = insn.address;

			cs_regs_access(cs_handle, &insn, regs_read, &read_count, regs_write, &write_count);
		}
		// get register read from
		// get value of register for instruction
	}

	// get value of the register x (might have to go back through the trace to find when it was last modified)
	
	// iterate through run trace, starting at the oldest executed instruction in it
	// check if any of the register modifications contain the same value as the one in the accessing register
	// identify register y used to assign to register x

	// repeat process with register y until static memory address is found
	

	/*
	for (size_t i = 0; i < 1; i++)
	{
		std::cout << std::endl;
		std::cout << "offending instruction:" << std::endl;
		std::cout << "address: " << insn[i].address << "\tmnemonic: " << insn[i].mnemonic << "\t" << insn[i].op_str << std::endl;
		if (insn[0].detail->regs_read_count > 0)
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

	cs_free(insn, cs_count);

		std::cout << "Eip is: " << std::hex << thread_context.Eip << std::endl;

	PrintRunTrace(offending_thread_ID);
	std::cout << "\n\n\n\n";
	*/

	return 1;
}

DWORD Tracer::GetValueOfRegisterForInstruction(DWORD thread_id, const char *reg_name, cs_insn insn, bool found)
{
	uint64_t address_of_instruction = insn.address;
	auto run_trace = all_threads_saved_instructions[thread_id];
	std::map<std::string, DWORD> modifications;

	for (auto ins = run_trace.rbegin(); ins != run_trace.rend(); ins++)
	{
		modifications = std::get<2>(*ins);

		auto modification = modifications.find(reg_name);

		if (modification != modifications.end())
		{
			found = true;
			return modification->second;
		}
	}

	found = false;
	return 0;
}

cs_insn Tracer::FindEarliestOccurenceOfValueInTrace(DWORD value)
{
	cs_insn insn;
	return insn;
}