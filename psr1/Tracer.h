#pragma once
#include "capstone.h"
#include <Windows.h>

class Tracer
{
public:
	Tracer();
	~Tracer();

	int SaveInstruction(uint8_t* instruction_buffer, DWORD thread_id, const CONTEXT& thread_context)
	int SaveInstructionInfo(uint8_t* instruction_buffer, size_t max_insn_size, DWORD thread_id, const CONTEXT& thread_context);
	int AnalyzeRunTrace(DWORD thread_id, EXCEPTION_RECORD exception_record);

	csh cs_handle;

private:
	int InitializeCapstone(); // maybe just put this in constructor? also set options for details
	DWORD GetValueOfRegisterForInstruction(DWORD thread_id, std::string reg_name, cs_insn insn, bool found);
	cs_insn FindEarliestOccurenceOfValueInTrace(DWORD thread_id, DWORD value);
	std::string GetRegisterReadFrom(DWORD thread_id, cs_insn insn);
	bool IsStaticAddress(DWORD value);

	std::map<DWORD, std::vector<std::tuple<DWORD, cs_insn, std::map<std::string, DWORD>>>> all_threads_saved_instructions;
	std::map<DWORD, CONTEXT> all_threads_saved_contexts;
	//const size_t x86_MAX_INSTRUCTION_LENGTH = 15;
	const size_t max_trace_length = 500;

};

