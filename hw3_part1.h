#pragma once

unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val);
unsigned long find_shared_symbol(char* symbol_name, char* exe_file_name);