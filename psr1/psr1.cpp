#include "stdafx.h"
#include <iostream>
#include <Windows.h>
#include "debugger.h"
#include <memory>


int main()
{
	DWORD target_pid;
	LPVOID target_address;

	std::cout << "Enter PID of target process: " << std::endl;
	std::cin >> target_pid;

	std::cout << "Enter address of interest in hexadecimal (without 0x): " << std::endl;
	std::cin >> std::hex >> target_address;

	std::unique_ptr<Debugger> debugger(new Debugger);
	debugger->SetTargetPID(target_pid);
	debugger->SetTargetAddress(target_address);

	debugger->Attach();
	//debugger->StartRunTraceRecording();
	while (TRUE)
	{
		debugger->SetMemoryBreakpoint(target_address);
		debugger->WaitForMemoryBreakpoint();
	}
	//debugger->AnalyzeRunTrace();

    return 0;
}
