#pragma once

#define	ET_NONE	0	//No file type 
#define	ET_REL	1	//Relocatable file 
#define	ET_EXEC	2	//Executable file 
#define	ET_DYN	3	//Shared object file 
#define	ET_CORE	4	//Core file 

unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val);
unsigned long find_shared_symbol(char* symbol_name, char* exe_file_name);
unsigned long do_nothing(char* symbol_name, char* exe_file_name);