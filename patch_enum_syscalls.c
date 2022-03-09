

static _inline void real_dprintf2(char *format, ...)
{
	va_list args;
	char buffer[1024];
	size_t len;
	_snprintf_s(buffer, sizeof(buffer), sizeof(buffer)-1, "[%x] ", GetCurrentThreadId());
	len = strlen(buffer);
	va_start(args, format);
	vsnprintf_s(buffer + len, sizeof(buffer)-len, sizeof(buffer)-len - 3, format, args);
	strcat_s(buffer, sizeof(buffer), "\r\n");
	OutputDebugStringA(buffer);
	va_end(args);
}


//#define DEBUGTRACE 1

#ifdef DEBUGTRACE
#define dprintf2(...) real_dprintf2(__VA_ARGS__)
#define dprintf(...) real_dprintf2(__VA_ARGS__)
#if DEBUGTRACE == 1
#define vdprintf dprintf
#else
#define vdprintf(...) do{}while(0);
#endif
#else
#define dprintf(...) do{}while(0);
#define dprintf2(...) do{}while(0);
#define vdprintf(...) do{}while(0);
#endif

static const unsigned int SYSCALL_ID_OFFSET = 4; // nb of bytes after a function's address that represents the syscall's id

// the strings below are written this way to prevent them from being stored in a different section of the executable.
/*static char NtCreateFile_api[] = { 'Z','w','C','r','e','a','t','e','F','i','l','e',0 };
static char NtAllocateVirtualMemory_api[] = { 'Z','w','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
static char NtAlpcConnectPort_api[] = { 'Z','w','A','l','p','c','C','o','n','n','e','c','t','P','o','r','t',0 };
static char NtAlpcConnectPortEx_api[] = { 'Z','w','A','l','p','c','C','o','n','n','e','c','t','P','o','r','t','E','x',0 };
static char NtAlpcSendWaitReceivePort_api[] = { 'Z','w','A','l','p','c','S','e','n','d','W','a','i','t','R','e','c','e','i','v','e','P','o','r','t',0 };
static char NtConnectPort_api[] = { 'Z','w','C','o','n','n','e','c','t','P','o','r','t',0 };
static char NtCreateSection_api[] = { 'Z','w','C','r','e','a','t','e','S','e','c','t','i','o','n',0 };
static char NtCreateThread_api[] = { 'Z','w','C','r','e','a','t','e','T','h','r','e','a','d',0 };
static char NtMapViewOfSection_api[] = { 'Z','w','M','a','p','V','i','e','w','O','f','S','e','c','t','i','o','n',0 };
static char NtProtectVirtualMemory_api[] = { 'Z','w','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
static char NtQueueApcThread_api[] = { 'Z','w','Q','u','e','u','e','A','p','c','T','h','r','e','a','d',0 };
static char NtRequestWaitReplyPort_api[] = { 'Z','w','R','e','q','u','e','s','t','W','a','i','t','R','e','p','l','y','P','o','r','t',0 };
static char NtResumeProcess_api[] = { 'Z','w','R','e','s','u','m','e','P','r','o','c','e','s','s',0 };
static char NtResumeThread_api[] = { 'Z','w','R','e','s','u','m','e','T','h','r','e','a','d',0 };
static char NtSecureConnectPort_api[] = { 'Z','w','S','e','c','u','r','e','C','o','n','n','e','c','t','P','o','r','t',0 };
static char NtSetContextThread_api[] = { 'Z','w','S','e','t','C','o','n','t','e','x','t','T','h','r','e','a','d',0 };
static char NtSetInformationThread_api[] = { 'Z','w','S','e','t','I','n','f','o','r','m','a','t','i','o','n','T','h','r','e','a','d',0 };
static char NtSuspendProcess_api[] = { 'Z','w','S','u','s','p','e','n','d','P','r','o','c','e','s','s',0 };
static char NtSuspendThread_api[] = { 'Z','w','S','u','s','p','e','n','d','T','h','r','e','a','d',0 };
static char NtCreateProcess_api[] = { 'Z','w','C','r','e','a','t','e','P','r','o','c','e','s','s',0 };
static char NtCreateProcessEx_api[] = { 'Z','w','C','r','e','a','t','e','P','r','o','c','e','s','s','E','x',0 };
static char NtCreateUserProcess_api[] = { 'Z','w','C','r','e','a','t','e','U','s','e','r','P','r','o','c','e','s','s',0 };
static char NtFreeVirtualMemory_api[] = { 'Z','w','F','r','e','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
static char NtQueueApcThreadEx_api[] = { 'Z','w','Q','u','e','u','e','A','p','c','T','h','r','e','a','d','E','x',0 };
static char NtReadVirtualMemory_api[] = { 'Z','w','R','e','a','d','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
static char NtSetInformationProcess_api[] = { 'Z','w','S','e','t','I','n','f','o','r','m','a','t','i','o','n','P','r','o','c','e','s','s',0 };
static char NtUnmapViewOfSection_api[] = { 'Z','w','U','n','m','a','p','V','i','e','w','O','f','S','e','c','t','i','o','n',0 };
*/

static char NtWriteVirtualMemory_api[] = { 'Z','w','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
static char NtCreateThreadEx_api[] = { 'Z','w','C','r','e','a','t','e','T','h','r','e','a','d','E','x',0 };
//static char NtWriteVirtualMemory_api[] = { 'a','r','a',0 };
//static char NtCreateThreadEx_api[] = { 'a','x',0 };


// store locations of strings on the stack
static const char* __API_names[] = {
	/*NtCreateFile_api,
	NtAllocateVirtualMemory_api,
	NtAlpcConnectPort_api,
	NtAlpcConnectPortEx_api,
	NtAlpcSendWaitReceivePort_api,
	NtConnectPort_api,
	NtCreateSection_api,
	NtCreateThread_api,*/
	NtCreateThreadEx_api,
	NtWriteVirtualMemory_api
	/*NtMapViewOfSection_api,
	NtProtectVirtualMemory_api,
	NtQueueApcThread_api,
	NtRequestWaitReplyPort_api,
	NtResumeProcess_api,
	NtResumeThread_api,
	NtSecureConnectPort_api,
	NtSetContextThread_api,
	NtSetInformationThread_api,
	NtSuspendProcess_api,
	NtSuspendThread_api,*/
	/*NtWriteVirtualMemory_api,
	NtCreateProcess_api,
	NtCreateProcessEx_api,
	NtCreateUserProcess_api,
	NtFreeVirtualMemory_api,
	NtQueueApcThreadEx_api,
	NtReadVirtualMemory_api,
	NtSetInformationProcess_api,
	NtUnmapViewOfSection_api*/
};


// groups useful infos about a given syscall
typedef struct _syscall_info {
	const char *name; // API name
	unsigned int id; // syscall ID: value passed to EAX in ntdll before issuing the 'syscall' instruction
} syscall_info;

static syscall_info* syscall_infos; // collection of syscalls
static BOOL syscalls_initialized = FALSE; // tracks initialization state

/*
 * compares two strings for strict equality
 *
 * \param string1 a string
 * \param string2 another string
 * \return 1 if the strings are equal, 0 otherwise.
 */
static int strequal(const char* string1, const char* string2)
{
	while (*string1 && *string2)

		if (*string1++ != *string2++)
			return 0;

	if (!*string1 && !*string2)
		return 1;

	return 0;
}

/*
 * allows to find a syscall by its name. Precondition: syscalls have been inited
 *
 * \param name the name of the API
 * \return infos about a syscall, such as its ID
 */
static syscall_info* get_syscall_by_name(const char* name)
{
	dprintf2("[nteav] get_syscall_by_name");

	SIZE_T nb_api_names = sizeof(__API_names) / sizeof(__API_names[0]);

	for (unsigned int i = 0; i < nb_api_names; i++)
	{
		if (strequal(syscall_infos[i].name, (const char*)name))
		{
			dprintf2("[nteav] syscall found");
			return &(syscall_infos[i]);
		}
	}

	dprintf2("[nteav] syscall not found !");

	return NULL;
}

//delete me
static void print_syscall(syscall_info* sinfo)
{
	dprintf2("[nteav] print_syscall");


	//convert to little endian (byte swap)
	unsigned char lvalue = sinfo->id & 255;
	unsigned char hvalue = (sinfo->id / 256) & 255;
	dprintf2("%08X  %s low = %02x high = %02x disass = ", sinfo->id, sinfo->name, lvalue, hvalue);

	unsigned char syscall_shellcode[] = {
		0x4c,0x8b,0xd1,
		0xb8,0x18,0x00,0x00,0x00,
		0x0f,0x05,
		0xc3
	};

	// update the shellcode with the correct syscall id
	syscall_shellcode[4] = lvalue;
	syscall_shellcode[5] = hvalue;

	// print the shellcode
	for (int i = 0; i < sizeof(syscall_shellcode) / sizeof(unsigned char); i++) {
		dprintf2(" %02x", syscall_shellcode[i]);
	}

	dprintf2("\n");
}


/*
 * see if confused about RVAs, VAs and file offsets https://github.com/deptofdefense/SalSA/wiki/PE-File-Format
 * in short, it is necessary to iterate over every section in the PE to find the one where the RVA lives.
 * Then, the RVA minus the section's virtual address allows to find an offset that can be added to the section's offset on disk...
 * the result is a new offset relative to the start of the file.
 */
static DWORD rva_to_file_offset(PIMAGE_SECTION_HEADER sections_headers, DWORD nb_sections, DWORD file_size, DWORD rva)
{
	PIMAGE_SECTION_HEADER current_section_header = sections_headers;
	DWORD i;
	for (i = 0; i < nb_sections; i++, current_section_header++)
	{
		if (rva >= sections_headers->VirtualAddress && rva <= (current_section_header->VirtualAddress + current_section_header->SizeOfRawData))
		{
			DWORD delta = rva - current_section_header->VirtualAddress;
			return current_section_header->PointerToRawData + delta;;
		}
	}

	return 0;
}

/*
 * read a file from disk
 *
 * \param file_path file location on disk
 * \param file_buffer result buffer pointing to the file's content
 * \param file_size result size of the file
 * \return TRUE if the file could be read
 */
static BOOL read_input_file(LPCSTR file_path, LPBYTE *file_buffer, unsigned long *file_size)
{
	dprintf2("[nteav] read_input_file");
	HANDLE handle_file_in = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	unsigned long bytes_read = 0;

	if (handle_file_in == INVALID_HANDLE_VALUE)
	{
		dprintf2("[!] Invalid handle value for target file, error = %d\n", GetLastError());
		return FALSE;
	}

	dprintf2("[nteav] open success");


	*file_size = GetFileSize(handle_file_in, NULL);
	*file_buffer = (LPBYTE)malloc(*file_size);
	ReadFile(handle_file_in, *file_buffer, *file_size, &bytes_read, 0);
	CloseHandle(handle_file_in);

	if (bytes_read != *file_size)
	{
		dprintf2("[!] Problem encountered while loading the target file in memory\n");
		VirtualFree(*file_buffer, bytes_read, MEM_RELEASE);
		return FALSE;
	}

	dprintf2("[nteav] read success");


	return TRUE;
}

/*
 * Locate the Export Directory in a given PE file
 *
 * \param file_buffer content of the PE file
 * \param file_size size of the PE file
 * \param first_section pointer to the first section's header in the PE file
 * \param nb_sections number of sections in the PE file
 * \return a pointer to the export directory
 */
static PIMAGE_EXPORT_DIRECTORY get_export_dir(LPBYTE file_buffer, DWORD file_size, PIMAGE_SECTION_HEADER *first_section, DWORD* nb_sections)
{
	dprintf2("[nteav] get_export_dir");

	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)file_buffer;

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		dprintf2("[!] Bad PE\n");
	}

	dprintf2("[nteav] good PE");

	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(file_buffer + dos_header->e_lfanew);
	*nb_sections = nt_header->FileHeader.NumberOfSections;

	*first_section = (PIMAGE_SECTION_HEADER)	(file_buffer + dos_header->e_lfanew +sizeof(IMAGE_NT_HEADERS));

	DWORD export_rva = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD export_file_offset = rva_to_file_offset(*first_section, *nb_sections, file_size, export_rva);

	return (PIMAGE_EXPORT_DIRECTORY)(file_buffer + export_file_offset);
}

/*
 * parses ntdll and populates the syscall_info structures
 *
 */
static void init_syscalls_ids()
{
	PBYTE file_buffer = NULL; //ntdll's content
	DWORD file_size = 0; //size of the dll

	dprintf2("[nteav] init_syscalls_ids");


	if (!read_input_file("c:\\windows\\system32\\ntdll.dll", &file_buffer, &file_size))
	{
		dprintf2("Error reading file.\n");
		return;
	}

	dprintf2("[nteav] read success");

	PIMAGE_SECTION_HEADER first_section; // first section's header, points to an array of sections headers.
	DWORD nb_sections = 0; // number of sections in ntdll

	PIMAGE_EXPORT_DIRECTORY export_directory = get_export_dir(file_buffer, file_size, &first_section, &nb_sections);

	PDWORD functions_address = (PDWORD)(file_buffer + rva_to_file_offset(first_section, nb_sections, file_size, export_directory->AddressOfFunctions));
	PWORD ordinals_address = (PWORD)(file_buffer + rva_to_file_offset(first_section, nb_sections, file_size, export_directory->AddressOfNameOrdinals));
	PDWORD names_address = (PDWORD)(file_buffer + rva_to_file_offset(first_section, nb_sections, file_size, export_directory->AddressOfNames));

	dprintf2("Id   Name     Low     High     Disass\n");
	dprintf2("--------------------------\n");

	SIZE_T nb_api_names = sizeof(__API_names) / sizeof(__API_names[0]);
	syscall_infos = (syscall_info*)malloc(nb_api_names * sizeof(syscall_info));

	for (DWORD i = 0; i < export_directory->NumberOfNames; ++i)
	{
		DWORD rva_api = functions_address[ordinals_address[i]];
		DWORD file_offset_name = rva_to_file_offset(first_section, nb_sections, file_size, names_address[i]);

		unsigned char* name = file_buffer + file_offset_name;

		/*
			windbg > u NtCreateFile
			ntdll!NtCreateFile:
			00007ffa`202458e0 4c8bd1          mov     r10,rcx
			00007ffa`202458e3 b855000000      mov     eax,55h
			00007ffa`202458e8 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
			00007ffa`202458f0 7503            jne     ntdll!NtCreateFile+0x15 (00007ffa`202458f5)
			00007ffa`202458f2 0f05            syscall
			00007ffa`202458f4 c3              ret
			00007ffa`202458f5 cd2e            int     2Eh
			00007ffa`202458f7 c3              ret
		 */

		 // filter everything except Zw* API functions
		if (!(*name == 'Z' && *(name + 1) == 'w'))
			continue;

		PBYTE procedure_address = file_buffer + rva_to_file_offset(first_section, nb_sections, file_size, rva_api);

		// get the syscall id
		DWORD syscall_id = *(DWORD *)(procedure_address + SYSCALL_ID_OFFSET);

		// filter according to suspicious API calls
		for (unsigned int i = 0; i < nb_api_names; i++)
		{
			if (strequal(__API_names[i], (const char*)name))
			{
				syscall_infos[i].name = __API_names[i];
				syscall_infos[i].id = syscall_id;
				print_syscall(&(syscall_infos[i]));
				break;
			}
		}
	}

	VirtualFree((LPVOID)file_buffer, file_size, MEM_RELEASE);
}

/*
 * get shellcode for a given syscall (native Zw/Nt API)
 *
 * \param name the syscall name (such as ZwCreateFile)
 * \return a buffer containing the shellcode, ready to be executed.
 */
static LPVOID get_shellcode_buffer(const char* name)
{

	dprintf2("[nteav] get_shellcode_buffer");

	if (!syscalls_initialized)
	{
		syscalls_initialized = TRUE;
		init_syscalls_ids();
	}

	dprintf2("[nteav] ready");

	syscall_info* syscall = get_syscall_by_name(name);

	if (syscall == NULL)
	{
		dprintf2("[nteav] No syscall found\n");
		return NULL;
	}

	unsigned int syscall_id = syscall->id;

	unsigned char syscall_shellcode[] = {
		0x4c,0x8b,0xd1,
		0xb8,0x18,0x00,0x00,0x00,
		0x0f,0x05,
		//0xb8, 0x01, 0x00, 0x00, 0x00,
		0xc3
	};

	//convert to little endian (byte swap)
	unsigned char lvalue = syscall_id & 255;
	unsigned char hvalue = (syscall_id / 256) & 255;

	// update the shellcode with the correct syscall id
	syscall_shellcode[4] = lvalue;
	syscall_shellcode[5] = hvalue;

	dprintf2("[nteav] generating shellcode");

	void *qapcmem = VirtualAlloc(0, sizeof(syscall_shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(qapcmem, syscall_shellcode, sizeof(syscall_shellcode));
	return qapcmem;
}
