#include "stdafx.h"
#include "Tracer.h"
#include <Windows.h>
#include <map>
#include <vector>
#include <string>

Tracer::Tracer()
	: cs_handle(NULL) // how to do this right? should we initialize handle to null or an actual handle value here?
{}


Tracer::~Tracer()
{}

int Tracer::SaveInstructionInfo(uint8_t* instruction_buffer, size_t max_insn_size, DWORD thread_id, const CONTEXT& thread_context)
{
	// instead of parsing now, lets just save raw code and parse after mem bp has been hit
	// would have to just save max_instruction_length worth of bytes from eip each time
	// then parse later and take insn[0] from each saved chunk
	SIZE_T num_bytes_read = 0;
	size_t cs_count = 0;
	cs_insn *insn;

	cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_count = cs_disasm(cs_handle, instruction_buffer, max_insn_size, thread_context.Eip, 0, &insn);

	std::tuple<DWORD, cs_insn, std::map<std::string, DWORD>> instruction;
	std::map<std::string, DWORD> modifications;

	//if (thread_context.Eip != all_threads_saved_contexts[thread_id].Eip) modifications["Eip"] = thread_context.Eip;
	if (thread_context.Eax != all_threads_saved_contexts[thread_id].Eax) modifications["Eax"] = thread_context.Eax;
	if (thread_context.Ebx != all_threads_saved_contexts[thread_id].Ebx) modifications["Ebx"] = thread_context.Ebx;
	if (thread_context.Ecx != all_threads_saved_contexts[thread_id].Ecx) modifications["Ecx"] = thread_context.Ecx;
	if (thread_context.Edx != all_threads_saved_contexts[thread_id].Edx) modifications["Edx"] = thread_context.Edx;
	if (thread_context.Edi != all_threads_saved_contexts[thread_id].Edi) modifications["Edi"] = thread_context.Edi;
	if (thread_context.Esi != all_threads_saved_contexts[thread_id].Esi) modifications["Esi"] = thread_context.Esi;

	if (cs_count > 0)
	{
		instruction = std::make_tuple(thread_context.Eip, insn[0], modifications);

		if (all_threads_saved_instructions[thread_id].size() >= max_trace_length)
		{
			all_threads_saved_instructions[thread_id].erase(all_threads_saved_instructions[thread_id].begin());
		}

		all_threads_saved_instructions[thread_id].push_back(instruction);
	}

	cs_free(insn, cs_count);

	return 1;
}

int Tracer::AnalyzeInstructions(cs_insn offending_instruction)
{
	// first, print whole trace
	// then, try to analyze trace based on read/written register in offending insn
	// if analysis is successful/useful, print the analysis

	return 1;
}