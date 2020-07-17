//
// Created by vladimir on 28.09.19.
//

#include <Windows.h>
#include <stdio.h>

char *customCommands[] =
{
	"core_loadlib",
    "request_core_loadlib",
	"core_enumextcmd",
    "request_core_enumextcmd",
	"core_machine_id",
    "request_core_machine_id",
	"core_get_session_guid",
    "request_core_get_session_guid"
};

typedef NTSTATUS (NTAPI *f_NtMapViewOfSection)(HANDLE, HANDLE, PVOID *, ULONG, ULONG,
PLARGE_INTEGER, PULONG, ULONG, ULONG, ULONG);
typedef NTSTATUS (* PKUHL_M_C_FUNC) (int argc, wchar_t * args[]);
typedef NTSTATUS (* PKUHL_M_C_FUNC_INIT) ();

typedef struct _KUHL_M_C {
    const PKUHL_M_C_FUNC pCommand;
    const wchar_t * command;
    const wchar_t * description;
} KUHL_M_C, *PKUHL_M_C;

int main(void)
{

    f_NtMapViewOfSection lNtMapViewOfSection;
    HMODULE ntdll;

    if (!(ntdll = LoadLibrary(TEXT("ntdll"))))
    {
        return -1;
    }

    lNtMapViewOfSection = (f_NtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
    lNtMapViewOfSection(0,0,0,0,0,0,0,0,0,0);

    char return_value[500];
    sprintf(return_value, "[*] Attempting to add user %s to host %s\n", "username", "dc_netbios_name");
    return 0;
}