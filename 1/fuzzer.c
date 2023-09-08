#include <stdio.h>
#include <process.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include <winnt.h>
#include <dbghelp.h>
#include <processthreadsapi.h>
#include <tlhelp32.h>
//#include <psapi.h>
#pragma comment(lib, "dbghelp.lib")

unsigned int menu() {
	puts("Choose what you like to do:\n"
		//"0: Add to file\n"
		"1: Change 1 byte\n"
		"2: Change 2 bytes\n"
		"3: Change 3 bytes\n"
		"4: Change 4 bytes\n");
	return getc(stdin) - 48;
}

bool get_info(unsigned int* shell_len, unsigned int* dst_len) {
	FILE* f;
	unsigned int buf[12] = { 0 };
	if (fopen_s(&f, "config_7", "rb")) {
		puts("Error open config file.");
		return false;
	}
	fseek(f, SEEK_SET, SEEK_CUR);
	fread(buf, sizeof(unsigned int), 12, f);
	//for (unsigned int i = 0; i < 12; i++)
		//printf("%u  ", buf[i]);
	*shell_len = buf[1];
	*dst_len = buf[2];
	fclose(f);
	return true;
}

/*
+	осуществл€ть изменение оригинального файла (однобайтова€ замена, замена нескольких байт, ///////////дозапись в файл);
+	замен€ть байты на граничные значени€ ( 0x00,  0xFF,  0xFFFF,  0xFFFFFF,  0xFFFFFFFF,  0xFFFF/2,  0xFFFF/2+1,  0xFFFF/2-1 и т.д.);
+	иметь автоматический режим работы, при котором производитс€ последовательна€ замена байт в файле;
?	находить в файле символы, раздел€ющие пол€ (У,:=;Ф);
+	расшир€ть значени€ полей в файле (дописывать в конец, увеличивать длину строк в файле);
?	находить границы полей в файле на основании анализа нескольких конфигурационных файлов;
+	осуществл€ть запуск исследуемой программы;
+	обнаруживать возникновение ошибки в исследуемом приложении;
+	получать код ошибки и состо€ни€ стека, регистров и другую информацию на момент возникновени€ ошибки;
+	логировать в файл информацию о произошедших ошибках и соответствующих им входных параметрах (произведенные замены).
*/

void Get_Registers_State(CONTEXT* hContext, const char* error, HANDLE hProcess) {
	FILE* log;
	if (fopen_s(&log, "log", "a")) {
		puts("Error open log file.");
		exit(-1);
	}
	fprintf(log, "\nException: %s\n", error);
	fprintf(log, "EAX: 0x%p ESP: 0x%p\n", (void*)hContext->Eax, (void*)hContext->Esp);
	fprintf(log, "EBX: 0x%p EBP: 0x%p\n", (void*)hContext->Ebx, (void*)hContext->Ebp);
	fprintf(log, "ECX: 0x%p EDI: 0x%p\n", (void*)hContext->Ecx, (void*)hContext->Edi);
	fprintf(log, "EDX: 0x%p ESI: 0x%p\n", (void*)hContext->Edx, (void*)hContext->Esi);
	fprintf(log, "EIP: 0x%p FLG: 0x%p\n", (void*)hContext->Eip, (void*)hContext->EFlags);
	// читаем из пам€ти по указателю на вершину стека (ESP) 
	/*unsigned char buffer[4048] = { 0 };
	SIZE_T recvSize = 0;
	if (ReadProcessMemory(hProcess, (void*)hContext->Esp, buffer, sizeof(buffer), &recvSize)/*recvSize*//* != 0) {
		fprintf(log, "\nStack (%d bytes read):\n", recvSize);

		for (unsigned int i = 0; i < recvSize; i++) {
			if ((i + 1) % 4 == 1)
				fprintf(log, "0x%p : ", (void*)((char*)hContext->Esp + i));
			if (buffer[i] < 0x10)
				fprintf(log, "0");
			fprintf(log, "%X ", (int)buffer[i]);
			if ((i + 1) % 4 == 0)
				fprintf(log, "\n");
		}
	}
	else
	{
		puts("ReadProcessMemory failed.");
		exit(-1);
	}*/
	fclose(log);
}

void run_program() {
	HANDLE hThread;
	PROCESS_INFORMATION proc_info;
	STARTUPINFO startup_info;
	BOOL status;
	CONTEXT hContext;
	DEBUG_EVENT debug_event = { 0 };
	RtlZeroMemory(&startup_info, sizeof(startup_info));
	startup_info.cb = sizeof(startup_info);
	status = CreateProcessA((LPCSTR)"vuln7.exe",
		NULL, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, (LPSTARTUPINFOA)&startup_info, &proc_info);
	if (status == false) {
		puts("CreateProcess failed.");
		exit(-1);
	}
	while (true) {
		// ожидаем событие отладки 
		status = WaitForDebugEvent(&debug_event, 500);
		if (status == false) {
			if (GetLastError() != ERROR_SEM_TIMEOUT)
				puts("WaitForDebugEvent failed.");
			break;
		}
		// смотрим код событи€ 
		if (debug_event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT) {
			// если это не исключение - продолжаем ожидать 
			ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
			continue;
			//return 0;
		}
		hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debug_event.dwThreadId);
		if (hThread == NULL) {
			puts("OpenThread failed.");
			break;
		}
		hContext.ContextFlags = CONTEXT_FULL;

		// по хэндлу получаем его контекст 
		status = GetThreadContext(hThread, &hContext);
		if (status == false) {
			puts("GethThreadContext failed.");
			CloseHandle(hThread);
			break;
		}
		switch (debug_event.u.Exception.ExceptionRecord.ExceptionCode) {
		case EXCEPTION_ACCESS_VIOLATION:
			Get_Registers_State(&hContext, "EXCEPTION_ACCESS_VIOLATION", proc_info.hProcess);
			break;
		case EXCEPTION_STACK_OVERFLOW:
			Get_Registers_State(&hContext, "EXCEPTION_STACK_OVERFLOW", proc_info.hProcess);
			break;
		case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
			Get_Registers_State(&hContext, "EXCEPTION_ARRAY_BOUNDS_EXCEEDED", proc_info.hProcess);
			break;
		case EXCEPTION_DATATYPE_MISALIGNMENT:
			Get_Registers_State(&hContext, "EXCEPTION_DATATYPE_MISALIGNMENT", proc_info.hProcess);
			break;
		case EXCEPTION_FLT_DENORMAL_OPERAND:
			Get_Registers_State(&hContext, "EXCEPTION_FLT_DENORMAL_OPERAND", proc_info.hProcess);
			break;
		case EXCEPTION_FLT_DIVIDE_BY_ZERO:
			Get_Registers_State(&hContext, "EXCEPTION_FLT_DIVIDE_BY_ZERO", proc_info.hProcess);
			break;
		case EXCEPTION_FLT_INEXACT_RESULT:
			Get_Registers_State(&hContext, "EXCEPTION_FLT_INEXACT_RESULT", proc_info.hProcess); \
			break;
		case EXCEPTION_FLT_INVALID_OPERATION:
			Get_Registers_State(&hContext, "EXCEPTION_FLT_INVALID_OPERATION", proc_info.hProcess);
			break;
		case EXCEPTION_FLT_OVERFLOW:
			Get_Registers_State(&hContext, "EXCEPTION_FLT_OVERFLOW", proc_info.hProcess);
			break;
		case EXCEPTION_FLT_STACK_CHECK:
			Get_Registers_State(&hContext, "EXCEPTION_FLT_STACK_CHECK", proc_info.hProcess);
			break;
		case EXCEPTION_FLT_UNDERFLOW:
			Get_Registers_State(&hContext, "EXCEPTION_FLT_UNDERFLOW", proc_info.hProcess);
			break;
		case EXCEPTION_ILLEGAL_INSTRUCTION:
			Get_Registers_State(&hContext, "EXCEPTION_ILLEGAL_INSTRUCTION", proc_info.hProcess);
			break;
		case EXCEPTION_IN_PAGE_ERROR:
			Get_Registers_State(&hContext, "EXCEPTION_IN_PAGE_ERROR", proc_info.hProcess);
			break;
		case EXCEPTION_INT_DIVIDE_BY_ZERO:
			Get_Registers_State(&hContext, "EXCEPTION_INT_DIVIDE_BY_ZERO", proc_info.hProcess);
			break;
		case EXCEPTION_INT_OVERFLOW:
			Get_Registers_State(&hContext, "EXCEPTION_INT_OVERFLOW", proc_info.hProcess);
			break;
		case EXCEPTION_INVALID_DISPOSITION:
			Get_Registers_State(&hContext, "EXCEPTION_INVALID_DISPOSITION", proc_info.hProcess);
			break;
		case EXCEPTION_NONCONTINUABLE_EXCEPTION:
			Get_Registers_State(&hContext, "EXCEPTION_NONCONTINUABLE_EXCEPTION", proc_info.hProcess);
			break;
		case EXCEPTION_PRIV_INSTRUCTION:
			Get_Registers_State(&hContext, "EXCEPTION_PRIV_INSTRUCTION", proc_info.hProcess);
			break;
		case EXCEPTION_SINGLE_STEP:
			Get_Registers_State(&hContext, "EXCEPTION_SINGLE_STEP", proc_info.hProcess);
			break;
		default:
			//cout << "Unknown exception: " << dec << debug_event.u.Exception.ExceptionRecord.ExceptionCode << endl;
			ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
		}
	}
	CloseHandle(proc_info.hProcess);
}

bool fuz(unsigned int task/*, unsigned int shell_len, unsigned int dst_len*/) {
	FILE* f;
	FILE* log;
	signed __int16 shell_len = 0;
	DWORD dst_len = 0;
	unsigned char bufer[48];
	unsigned int amount;
	unsigned int pos;
	switch (task)
	{
	/*case 0: { //add to file
		if (fopen_s(&f, "config_7", "a+")) {
			puts("Error open config file.");
			return false;
		}

		unsigned int size_in = dst_len - shell_len + 16;
		char* buf = (char*)malloc(dst_len + 16);
		if (!buf) {
			puts("Error allocate memory.");
			return false;
		}
		char* input = (char*)malloc(size_in);
		if (!input) {
			puts("Error allocate memory.");
			return false;
		}

		fseek(f, 0, SEEK_END);
		unsigned int pos = ftell(f); //find size of file
		memset(input, 'a', size_in); //create overflow string
		fwrite(input, sizeof(char), size_in, f);
		fputc(EOF, f);
		puts("Config was changed.");
		fclose(f);
		free(input);
		free(buf);
		run_program("vuln7.exe");
		fclose(f);
		return true;
	}*/
	//change file
	case 1: {//change 1 byte
		if (fopen_s(&f, "config_7", "r+b")) {
			puts("Error open config file.");
			return false;
		}
		if (fopen_s(&log, "log", "w")) {
			puts("Error open log file.");
			return false;
		}

		unsigned char change_1byte[4] = { '\x00', '\x80', '\x7f', '\xff' }; //{"0x00000000", "0x80000000", "0x7FFFFFFF", "0xFFFFFFFF"};
		amount = 1;
		for (unsigned int i = 0; i < 4; i++) {
			fprintf(log, "\n\nChange %d byte for %02x\n", amount, (unsigned int)change_1byte[i]);
			fseek(f, 0, SEEK_SET); //switched from read to write
			fseek(f, 0, SEEK_SET); //switched from write to read
			fread(bufer, sizeof(char), 48, f); //read bufer

			fprintf(log, "Original string: ");
			for (unsigned int h = 0; h < 48; h++)
				fprintf(log, "%02x ", (unsigned int)bufer[h]);

			fseek(f, 0, SEEK_SET); //switched from read to write
			for (unsigned int j = 0; j < 48; j++) {
				pos = ftell(f);
				fwrite(&change_1byte[i], sizeof(unsigned char), amount, f); //put new symbol

				fprintf(log, "\nNew string: ");
				for (unsigned int h = 0; h < 48; h++) {
					if (h == j) {
						fprintf(log, "%02x ", (unsigned int)change_1byte[i]);
					}
					else fprintf(log, "%02x ", (unsigned int)bufer[h]);
				}

				fseek(f, sizeof(signed __int16) * 8, SEEK_SET); //switched from write to read
				fread(&shell_len, sizeof(signed __int16), 1, f);
				fseek(f, sizeof(DWORD) * 2, SEEK_SET); //switched from read to write
				fseek(f, 0, SEEK_CUR); //switched from write to read
				fread(&dst_len, sizeof(DWORD), 1, f);
				fprintf(log, "\nshell_len = %d, dst_len = %d", shell_len, dst_len);

				fclose(f);
				fclose(log);
				run_program("vuln7.exe"); //test
				if (fopen_s(&log, "log", "a")) {
					puts("Error open log file.");
					return false;
				}
				if (fopen_s(&f, "config_7", "r+b")) {
					puts("Error open config file.");
					return false;
				}
				fseek(f, pos, SEEK_CUR); //switched from read to write
				fputc(bufer[j], f); //restore original string

			}
		}
		fclose(f);
		fclose(log);
		return true;
	}
	case 2: {//change 2 bytes
		if (fopen_s(&f, "config_7", "r+b")) {
			puts("Error open config file.");
			return false;
		}
		if (fopen_s(&log, "log", "w")) {
			puts("Error open log file.");
			return false;
		}
		unsigned char change_2bytes[4][2] = { "\x00\x00", "\x80\x00", "\x7f\xff", "\xff\xff" }; //{"0x00000000", "0x80000000", "0x7FFFFFFF", "0xFFFFFFFF"};
		amount = 2;
		for (unsigned int i = 0; i < 4; i++) {
			fprintf(log, "\n\nChange %d bytes for %02x %02x\n", amount, (unsigned int)change_2bytes[i][0],
				(unsigned int)change_2bytes[i][1]);
			fseek(f, 0, SEEK_SET); //switched from read to write
			fseek(f, 0, SEEK_SET); //switched from write to read
			fread(bufer, sizeof(char), 48, f); //read bufer

			fprintf(log, "Original string: ");
			for (unsigned int h = 0; h < 48; h++)
				fprintf(log, "%02x ", (unsigned int)bufer[h]);

			fseek(f, 0, SEEK_SET); //switched from read to write
			for (unsigned int j = 0; j < 48; j += amount) {
				pos = ftell(f);
				fwrite(&change_2bytes[i], sizeof(unsigned char), amount, f); //put new symbol

				fprintf(log, "\nNew string: ");
				for (unsigned int h = 0; h < 48; h++) {
					if (h == j) {
						fprintf(log, "%02x ", (unsigned int)change_2bytes[i][0]);
						fprintf(log, "%02x ", (unsigned int)change_2bytes[i][1]);
						h++;
					}
					else fprintf(log, "%02x ", (unsigned int)bufer[h]);
				}

				fseek(f, sizeof(signed __int16) * 8, SEEK_SET); //switched from write to read
				fread(&shell_len, sizeof(signed __int16), 1, f);
				fseek(f, sizeof(DWORD) * 2, SEEK_SET); //switched from read to write
				fseek(f, 0, SEEK_CUR); //switched from write to read
				fread(&dst_len, sizeof(DWORD), 1, f);
				fprintf(log, "\nshell_len = %d, dst_len = %d", shell_len, dst_len);

				fclose(f);
				fclose(log);
				run_program("vuln7.exe"); //test
				if (fopen_s(&log, "log", "a")) {
					puts("Error open log file.");
					return false;
				}
				if (fopen_s(&f, "config_7", "r+b")) {
					puts("Error open config file.");
					return false;
				}
				fseek(f, pos, SEEK_CUR); //switched from read to write
				fputc(bufer[j], f); //restore original string
				fputc(bufer[j + 1], f);
			}
		}
		fclose(f);
		fclose(log);
		return true;
	}
	case 3: {//change 3 bytes
		if (fopen_s(&f, "config_7", "r+b")) {
			puts("Error open config file.");
			return false;
		}
		if (fopen_s(&log, "log", "w")) {
			puts("Error open log file.");
			return false;
		}
		unsigned char change_3bytes[4][3] = { "\x00\x00\x00", "\x80\x00\x00", "\x7f\xff\xff", "\xff\xff\xff" }; //{"0x00000000", "0x80000000", "0x7FFFFFFF", "0xFFFFFFFF"};
		amount = 3;
		for (unsigned int i = 0; i < 4; i++) {
			fprintf(log, "\n\nChange %d bytes for %02x %02x %02x\n", amount, (unsigned int)change_3bytes[i][0],
				(unsigned int)change_3bytes[i][1], (unsigned int)change_3bytes[i][2]);
			fseek(f, 0, SEEK_SET); //switched from read to write
			fseek(f, 0, SEEK_SET); //switched from write to read
			fread(bufer, sizeof(char), 48, f); //read bufer

			fprintf(log, "Original string: ");
			for (unsigned int h = 0; h < 48; h++)
				fprintf(log, "%02x ", (unsigned int)bufer[h]);

			fseek(f, 0, SEEK_SET); //switched from read to write
			for (unsigned int j = 0; j < 48; j += amount) {
				pos = ftell(f);
				fwrite(&change_3bytes[i], sizeof(unsigned char), amount, f); //put new symbol

				fprintf(log, "\nNew string: ");
				for (unsigned int h = 0; h < 48; h++) {
					if (h == j) {
						for (unsigned int k = 0; k < amount; k++)
							fprintf(log, "%02x ", (unsigned int)change_3bytes[i][k]);
						h += 2;
					}
					else fprintf(log, "%02x ", (unsigned int)bufer[h]);
				}

				fseek(f, sizeof(signed __int16) * 8, SEEK_SET); //switched from write to read
				fread(&shell_len, sizeof(signed __int16), 1, f);
				fseek(f, sizeof(DWORD) * 2, SEEK_SET); //switched from read to write
				fseek(f, 0, SEEK_CUR); //switched from write to read
				fread(&dst_len, sizeof(DWORD), 1, f);
				fprintf(log, "\nshell_len = %d, dst_len = %d", shell_len, dst_len);

				fclose(f);
				fclose(log);
				run_program("vuln7.exe"); //test
				if (fopen_s(&log, "log", "a")) {
					puts("Error open log file.");
					return false;
				}
				if (fopen_s(&f, "config_7", "r+b")) {
					puts("Error open config file.");
					return false;
				}
				fseek(f, pos, SEEK_CUR); //switched from write to read
				fseek(f, 0, SEEK_CUR); //switched from read to write
				fputc(bufer[j], f);
				fputc(bufer[j + 1], f);
				fputc(bufer[j + 2], f);
			}
		}
		fclose(f);
		fclose(log);
		return true;
	}
	case 4: {//change 4 bytes
		if (fopen_s(&f, "config_7", "r+b")) {
			puts("Error open config file.");
			return false;
		}
		if (fopen_s(&log, "log", "w")) {
			puts("Error open log file.");
			return false;
		}
		unsigned char change_4bytes[4][4] = { "\x00\x00\x00\x00", "\x80\x00\x00\x00", "\x7f\xff\xff\xff", "\xff\xff\xff\xff" }; //{"0x00000000", "0x80000000", "0x7FFFFFFF", "0xFFFFFFFF"};
		for (unsigned int i = 0; i < 4; i++) {
			unsigned int amount = 4;
			fprintf(log, "\n\nChange %d bytes for %02x %02x %02x %02x\n", amount, (unsigned int)change_4bytes[i][0],
				(unsigned int)change_4bytes[i][1], (unsigned int)change_4bytes[i][2], (unsigned int)change_4bytes[i][3]);
			fseek(f, 0, SEEK_SET); //switched from read to write
			fseek(f, 0, SEEK_SET); //switched from write to read
			fread(bufer, sizeof(char), 48, f); //read bufer

			fprintf(log, "Original string: ");
			for (unsigned int h = 0; h < 48; h++)
				fprintf(log, "%02x ", (unsigned int)bufer[h]);

			fseek(f, 0, SEEK_SET); //switched from read to write
			for (unsigned int j = 0; j < 48; j += amount) {
				pos = ftell(f);
				fwrite(&change_4bytes[i], sizeof(unsigned char), amount, f); //put new symbol

				fprintf(log, "\nNew string: ");
				for (unsigned int h = 0; h < 48; h++) {
					if (h == j) {
						for (unsigned int k = 0; k < amount; k++)
							fprintf(log, "%02x ", (unsigned int)change_4bytes[i][k]);
						h += 3;
					}
					else fprintf(log, "%02x ", (unsigned int)bufer[h]);
				}

				fseek(f, sizeof(signed __int16) * 8, SEEK_SET); //switched from write to read
				fread(&shell_len, sizeof(signed __int16), 1, f);
				fseek(f, sizeof(DWORD) * 2, SEEK_SET); //switched from read to write
				fseek(f, 0, SEEK_CUR); //switched from write to read
				fread(&dst_len, sizeof(DWORD), 1, f);
				fprintf(log, "\nshell_len = %d, dst_len = %d", shell_len, dst_len);

				fclose(f);
				fclose(log);
				run_program("vuln7.exe"); //test
				if (fopen_s(&log, "log", "a")) {
					puts("Error open log file.");
					return false;
				}
				if (fopen_s(&f, "config_7", "r+b")) {
					puts("Error open config file.");
					return false;
				}
				fseek(f, pos, SEEK_CUR); //switched from write to read
				fseek(f, 0, SEEK_CUR); //switched from read to write
				fputc(bufer[j], f);
				fputc(bufer[j + 1], f);
				fputc(bufer[j + 2], f);
				fputc(bufer[j + 3], f);
			}
		}
		fclose(f);
		fclose(log);
	}
	default:
		break;
	}
	return true;
}

int main() {
	unsigned int shell_len = 0, dst_len = 0;
	if (get_info(&shell_len, &dst_len)) {
		puts("Information was successfully read.");
		unsigned int task = menu();
		if (fuz(task/*, shell_len, dst_len*/)) {
			puts("Fuzzing complete.");
			return 0;
		}
		else return -1;
	}
	else return -1;
}