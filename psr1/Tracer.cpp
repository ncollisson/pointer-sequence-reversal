#include "stdafx.h"
#include "Tracer.h"
#include "debugger.h"

#define MAX_INSN_LENGTH 16


Tracer::Tracer()
	: cs_handle(NULL) // how to do this right? should we initialize handle to null or an actual handle value here?
{
	InitializeCapstone();
}

int Tracer::InitializeCapstone()
{
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle) != CS_ERR_OK) std::cout << "Error in cs_open()" << std::endl;
	cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

	return 1;
}


Tracer::~Tracer()
{}
/*
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
		instruction = std::make_tuple(thread_context.Eip, insn, modifications);

		if (all_threads_saved_instructions[thread_id].size() >= max_trace_length)
		{
			all_threads_saved_instructions[thread_id].erase(all_threads_saved_instructions[thread_id].begin());
		}

		all_threads_saved_instructions[thread_id].push_back(instruction);
	}

	cs_free(insnp, cs_count);

	return 1;
}*/

int Tracer::SaveInstruction(uint8_t* instruction_buffer, DWORD thread_id, const CONTEXT& thread_context)
{
	DWORD previous_eip = 0,
		current_eip = thread_context.Eip;

	if (!all_threads_saved_instructions[thread_id].empty())
	{
		// get<0> since eip (i.e., address) for an instruction is first element of instrution tuple
		previous_eip = std::get<0>(all_threads_saved_instructions[thread_id].back());
	}

	// check that prev eip and current eip dont match, or else mem bp triggering instructions will get added twice
	if (previous_eip != current_eip)
	{
		//std::tuple<DWORD, std::array<uint8_t, MAX_INSN_LENGTH>, std::map<std::string, DWORD>> instruction;
		std::map<std::string, DWORD> modifications;

		//if (thread_context.Eip != all_threads_saved_contexts[thread_id].Eip) modifications["Eip"] = thread_context.Eip;
		if (thread_context.Eax != all_threads_saved_contexts[thread_id].Eax) modifications["Eax"] = thread_context.Eax;
		if (thread_context.Ebx != all_threads_saved_contexts[thread_id].Ebx) modifications["Ebx"] = thread_context.Ebx;
		if (thread_context.Ecx != all_threads_saved_contexts[thread_id].Ecx) modifications["Ecx"] = thread_context.Ecx;
		if (thread_context.Edx != all_threads_saved_contexts[thread_id].Edx) modifications["Edx"] = thread_context.Edx;
		if (thread_context.Edi != all_threads_saved_contexts[thread_id].Edi) modifications["Edi"] = thread_context.Edi;
		if (thread_context.Esi != all_threads_saved_contexts[thread_id].Esi) modifications["Esi"] = thread_context.Esi;

		all_threads_saved_contexts[thread_id] = thread_context;

		std::array<uint8_t, MAX_INSN_LENGTH> insn_buffer = { 0 };

		for (unsigned int i = 0; i < MAX_INSN_LENGTH; i++)
		{
			insn_buffer[i] = instruction_buffer[i];
		}

		auto instruction = std::make_tuple(thread_context.Eip, insn_buffer, modifications);

		if (all_threads_saved_instructions[thread_id].size() >= max_trace_length)
		{
			all_threads_saved_instructions[thread_id].erase(all_threads_saved_instructions[thread_id].begin());
		}

		all_threads_saved_instructions[thread_id].push_back(instruction);
	}

	return 1;
}

cs_insn Tracer::GetCsInsnFromBytes(std::array<uint8_t, MAX_INSN_LENGTH> insn_bytes, DWORD address)
{
	uint8_t insn_buf[MAX_INSN_LENGTH] = { 0 };
	size_t count = 0;
	cs_insn insn;
	cs_insn *insnp;

	for (size_t i = 0; i < MAX_INSN_LENGTH; i++)
	{
		insn_buf[i] = insn_bytes[i];
	}

	count = cs_disasm(cs_handle, insn_buf, MAX_INSN_LENGTH, address, count, &insnp);
	insn = insnp[0];

	return insn;
}

int Tracer::AnalyzeRunTrace(DWORD thread_id, EXCEPTION_RECORD exception_record)
{
	std::string reg_name;
	bool analysis_succeeded = false, found = false;
	cs_insn insn;
	DWORD address;
	run_trace_vec run_trace = all_threads_saved_instructions[thread_id];

	std::array<uint8_t, MAX_INSN_LENGTH> raw_insn = std::get<1>(run_trace.back());
	address = std::get<0>(run_trace.back());

	insn = GetCsInsnFromBytes(raw_insn, address);

	size_t trace_pos = run_trace.end() - run_trace.begin() - 1;

	if (exception_record.ExceptionInformation[0] == 0) // true when the memory access violation was a read
	{
		reg_name = GetRegisterReadFrom(thread_id, insn, trace_pos);
	}
	else
	{
		// dont think capstone can identify regs written to very well
		// dont even try for now
		return 0;
	}

	DWORD value;
	uint64_t last_insn_address = 0;
	std::vector<std::pair<cs_insn, DWORD>> relevant_instructions;

	while (!analysis_succeeded)
	{
		value = GetValueOfRegisterForInstruction(thread_id, reg_name, insn, found, trace_pos);
		if (!found) break;
		found = false;

		relevant_instructions.push_back(std::make_pair(insn, value));

		if (IsStaticAddress(value)) // or whatever other condition means success
		{
			analysis_succeeded = true;
			break;
		}

		//trace_pos = FindEarliestOccurenceOfValueInTrace(thread_id, value); // returns instruction position in trace
		trace_pos = FindMostRecentOccurenceOfValueInTrace(thread_id, value, trace_pos);
		if (trace_pos == 0) break;

		raw_insn = std::get<1>(run_trace.at(trace_pos));
		address = std::get<0>(run_trace.at(trace_pos));

		insn = GetCsInsnFromBytes(raw_insn, address);

		if (insn.address == last_insn_address) break; // this might more correct using trace_pos instead of address
		last_insn_address = insn.address;

		reg_name = GetRegisterReadFrom(thread_id, insn, trace_pos);
		if (reg_name == "No registers read")
		{
			relevant_instructions.push_back(std::make_pair(insn, value));
			break;
		}

		if (GetAsyncKeyState(0x51)) break;
	}

	if (analysis_succeeded)
	{
		std::cout << "successful trace completed" << std::endl;

		for (auto ins = relevant_instructions.rbegin(); ins != relevant_instructions.rend(); ins++)
		{
			auto rel_insn = *ins;
			std::cout << rel_insn.first.address << std::hex << "\t" << rel_insn.first.mnemonic << " ";
			std::cout << rel_insn.first.op_str << "\t\t" << std::hex << rel_insn.second << std::endl;
		}

		std::cout << "-------- end of trace --------" << std::endl;
	}
	else
	{
		std::cout << "trace analysis completed" << std::endl;

		for (auto ins = relevant_instructions.rbegin(); ins != relevant_instructions.rend(); ins++)
		{
			auto rel_insn = *ins;
			std::cout << rel_insn.first.address << std::hex << "\t" << rel_insn.first.mnemonic << " ";
			std::cout << rel_insn.first.op_str << "\t\t" << std::hex << rel_insn.second << std::endl;
		}

		std::cout << "-------- end of trace --------" << std::endl;
	}

		
	// now what to do with analysis? should be saving info along the way

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

bool Tracer::IsStaticAddress(DWORD value)
{
	if (value >= 0x400000 && value <= 0xA3D000) return true;

	return false;
}

std::string Tracer::GetRegisterReadFrom(DWORD thread_id, cs_insn insn, const size_t trace_pos)
{
	std::string reg_name = "No registers read", temp_reg_name, op_str = insn.op_str;
	cs_regs regs_read, regs_write;
	uint8_t read_count, write_count;
	unsigned int reg_count = 0;

	std::vector<std::string> my_regs_read;
	
	cs_regs_access(cs_handle, &insn, regs_read, &read_count, regs_write, &write_count);

	if (read_count > 0)
	{
		bool found = false;

		// figure out what to do about instructions like "mov eax, [ecx + edx * 4]"
		// probably want to guess that register with higher value contains useful address
		DWORD this_value = 0, last_value = 0;

		for (int i = 0; i < read_count; i++)
		{
			temp_reg_name = cs_reg_name(cs_handle, regs_read[i]);
			temp_reg_name[0] = toupper(temp_reg_name[0]);

			this_value = GetValueOfRegisterForInstruction(thread_id, temp_reg_name.c_str(), insn, found, trace_pos);

			if (this_value >= last_value)
			{
				reg_name = temp_reg_name;
				last_value = this_value;
			}
		}
	}

	reg_name[0] = toupper(reg_name[0]);

	return reg_name;
}

DWORD Tracer::GetValueOfRegisterForInstruction(DWORD thread_id, std::string reg_name, cs_insn insn, bool& found, const size_t start_trace_pos)
{
	uint64_t address_of_instruction = insn.address;
	//auto run_trace = all_threads_saved_instructions[thread_id];
	std::map<std::string, DWORD> modifications;
	run_trace_vec run_trace = all_threads_saved_instructions[thread_id];

	//std::reverse_iterator<std::vector<instruction_info>::iterator> trace_it = run_trace.rend() - start_trace_pos;

	for (size_t trace_pos = start_trace_pos; trace_pos > 0; trace_pos--)
	{
		instruction_info insn_info = run_trace.at(trace_pos);
		modifications = std::get<2>(insn_info);

		auto modification = modifications.find(reg_name.c_str());

		if (modification != modifications.end())
		{
			found = true;
			return modification->second;
		}
	}

	found = false;
	return 0;
}

size_t Tracer::FindEarliestOccurenceOfValueInTrace(DWORD thread_id, DWORD value)
{
	run_trace_vec run_trace = all_threads_saved_instructions[thread_id];
	cs_insn *insnp;
	DWORD address;
	std::array<uint8_t, MAX_INSN_LENGTH> raw_insn;
	size_t count = 0;
	std::map<std::string, DWORD> modifications;
	uint8_t raw_insn_buf[MAX_INSN_LENGTH] = { 0 };
	size_t trace_pos = 0;

	for (size_t trace_pos = 0; trace_pos < run_trace.size(); trace_pos++)
	{
		instruction_info insn_info = run_trace.at(trace_pos);
		modifications = std::get<2>(insn_info);

		for (auto mod = modifications.begin(); mod != modifications.end(); mod++)
		{
			if (mod->second == value && trace_pos != 0)
			{
				// just decrement ins iterator and grab prev instruction
				size_t prev_trace_pos = trace_pos - 1;
				instruction_info prev_insn_info = run_trace.at(prev_trace_pos);
				/*
				address = std::get<0>(prev_insn_info);
				raw_insn = std::get<1>(prev_insn_info);

				for (size_t i = 0; i < MAX_INSN_LENGTH; i++)
				{
					raw_insn_buf[i] = raw_insn[i];
				}

				count = cs_disasm(cs_handle, raw_insn_buf, MAX_INSN_LENGTH, address, count, &insnp);
				*/
				return prev_trace_pos;
			}
		}
	}

	// should do something about error condition
	return 0;
}

size_t Tracer::FindMostRecentOccurenceOfValueInTrace(DWORD thread_id, DWORD value, size_t start_trace_pos)
{
	run_trace_vec run_trace = all_threads_saved_instructions[thread_id];
	std::map<std::string, DWORD> modifications;
	DWORD address;
	std::array<uint8_t, MAX_INSN_LENGTH> raw_insn;
	uint8_t raw_insn_buf[MAX_INSN_LENGTH] = { 0 };
	size_t count = 0;
	cs_insn *insnp;
	cs_insn insn;
	cs_regs regs_read, regs_write;
	uint8_t read_count, write_count;
	std::string reg_read;
	bool reg_read_is_stack_reg = true;
	size_t rel_trace_pos = 0;

	for (size_t trace_pos = start_trace_pos; trace_pos > 0; trace_pos--)
	{
		instruction_info insn_info = run_trace.at(trace_pos);
		modifications = std::get<2>(insn_info);

		for (auto mod = modifications.begin(); mod != modifications.end(); mod++)
		{
			if (mod->second == value && trace_pos != 0)
			{
				// just decrement ins iterator and grab prev instruction
				size_t prev_trace_pos = trace_pos - 1;
				instruction_info prev_insn_info = run_trace.at(prev_trace_pos);
				
				address = std::get<0>(prev_insn_info);
				raw_insn = std::get<1>(prev_insn_info);

				for (size_t i = 0; i < MAX_INSN_LENGTH; i++) raw_insn_buf[i] = raw_insn[i];

				count = cs_disasm(cs_handle, raw_insn_buf, MAX_INSN_LENGTH, address, count, &insnp);
				insn = insnp[0];

				if (count > 0)
				{
					reg_read = GetRegisterReadFrom(thread_id, insn, prev_trace_pos);

					if (reg_read == "Esp" || reg_read == "Ebp")
					{
						reg_read_is_stack_reg = true;
					}
					else
					{
						reg_read_is_stack_reg = false;
						rel_trace_pos = prev_trace_pos;
					}
				}

				break; // maybe break only if reg read is good
			}
		}

		if (!reg_read_is_stack_reg) return rel_trace_pos;
	}

	return rel_trace_pos;
}