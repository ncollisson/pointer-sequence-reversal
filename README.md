# pointer-chain-reversal

Designed to help a reverse engineer easily see how a Windows C++ application is accessing a particular data member or object.

Given the memory address of a data member or object, this tool will set a memory breakpoint at that address and then produce traces of the instructions executed prior to reading from or writing to that address. Some processing will be performed on the trace to highlight relevant instructions, make the output more readable, identify vtable pointers, etc.

This tool performs roughly the same task as the pointer scanner functionality found in Cheat Engine, except it works "upwards" towards the top of the pointer chain instead of "downwards", as Cheat Engine's pointer scanner does. This approach will hopefully be faster and more accurate.
