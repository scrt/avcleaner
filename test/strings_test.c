#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <Winldap.h>
#include <stdio.h>
#include "common_base.h"

NTSTATUS CALLBACK kuhl_m_lsadump_setntlm_callback(PVOID hUser, PVOID pvArg)
{
	NTSTATUS status = LoadLibrary(TEXT("ntdll"));
	if(NT_SUCCESS(status))
		wprintf(L"\n>> Informations are in the target SAM!\n");
	else printf(L"SamSetInformationUser: %08x\n", status);
	return status;
}

#define szOID_ldapServer_show_deleted		"1.2.840.113556.1.4.417"

DWORD request_core_loadlib( Remote * pRemote, Packet * pPacket );
BOOL request_core_patch_url(Remote* remote, Packet* packet, DWORD* result);

typedef struct _CryptProviderParams
{
	const TCHAR* provider;
	const DWORD type;
	const DWORD flags;
} CryptProviderParams;


// Dispatch table
Command customCommands[] =
        {
                COMMAND_REQ("core_loadlib", request_core_loadlib),
                COMMAND_REQ("core_loadlib", request_core_loadlib),
                COMMAND_REQ("core_enumextcmd", request_core_loadlib),
                COMMAND_REQ("core_machine_id", request_core_loadlib),
                COMMAND_REQ("core_get_session_guid", request_core_loadlib),
                COMMAND_REQ("core_set_session_guid", request_core_loadlib),
                COMMAND_REQ("core_set_uuid", request_core_loadlib),
                COMMAND_REQ("core_pivot_add", request_core_loadlib),
                COMMAND_REQ("core_pivot_remove", request_core_loadlib),
                COMMAND_INLINE_REP("core_patch_url", request_core_patch_url),
                COMMAND_TERMINATOR
        };

DWORD request_core_loadlib( Remote * pRemote, Packet * pPacket ) {
    return 0;
}

BOOL request_core_patch_url(Remote* remote, Packet* packet, DWORD* result){
    return TRUE;
}

const CryptProviderParams AesProviders[] =
{
	{MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0},
	{MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET},
	{MS_ENH_RSA_AES_PROV_XP, PROV_RSA_AES, 0},
	{MS_ENH_RSA_AES_PROV_XP, PROV_RSA_AES, CRYPT_NEWKEYSET}
};

// if the library was loaded via its reflective loader we must use GetProcAddressR()
/*
    pExtension->init = (PSRVINIT)GetProcAddressR(pExtension->library, "InitServerExtension");
    pExtension->deinit = (PSRVDEINIT)GetProcAddressR(pExtension->library, "DeinitServerExtension");
    pExtension->getname = (PSRVGETNAME)GetProcAddressR(pExtension->library, "GetExtensionName");
    pExtension->commandAdded = (PCMDADDED)GetProcAddressR(pExtension->library, "CommandAdded");
    pExtension->stagelessInit = (PSTAGELESSINIT)GetProcAddressR(pExtension->library, "StagelessInit");
*/
typedef NTSTATUS (NTAPI *f_NtMapViewOfSection)(HANDLE, HANDLE, PVOID *, ULONG, ULONG,
		PLARGE_INTEGER, PULONG, ULONG, ULONG, ULONG);
typedef NTSTATUS (* PKUHL_M_C_FUNC) (int argc, wchar_t * args[]);
typedef NTSTATUS (* PKUHL_M_C_FUNC_INIT) ();

typedef struct _KUHL_M_C {
	const PKUHL_M_C_FUNC pCommand;
	const wchar_t * command;
	const wchar_t * description;
} KUHL_M_C, *PKUHL_M_C;

DWORD request_sys_config_getprivs(Remote *remote, Packet *packet)
{
	//Packet *response = packet_create_response(packet);
	DWORD res = ERROR_SUCCESS;
	HANDLE token = NULL;
	int x;
	TOKEN_PRIVILEGES priv = { 0 };
	LPCTSTR privs[] = {
		SE_ASSIGNPRIMARYTOKEN_NAME,
		SE_AUDIT_NAME,
		SE_BACKUP_NAME,
		SE_CHANGE_NOTIFY_NAME,
		SE_CREATE_GLOBAL_NAME,
		SE_CREATE_PAGEFILE_NAME,
		SE_CREATE_PERMANENT_NAME,
		SE_CREATE_SYMBOLIC_LINK_NAME,
		SE_CREATE_TOKEN_NAME,
		SE_DEBUG_NAME,
		SE_ENABLE_DELEGATION_NAME,
		SE_IMPERSONATE_NAME,
		SE_INC_BASE_PRIORITY_NAME,
		SE_INCREASE_QUOTA_NAME,
		SE_INC_WORKING_SET_NAME,
		SE_LOAD_DRIVER_NAME,
		SE_LOCK_MEMORY_NAME,
		SE_MACHINE_ACCOUNT_NAME,
		SE_MANAGE_VOLUME_NAME,
		SE_PROF_SINGLE_PROCESS_NAME,
		SE_RELABEL_NAME,
		SE_REMOTE_SHUTDOWN_NAME,
		SE_RESTORE_NAME,
		SE_SECURITY_NAME,
		SE_SHUTDOWN_NAME,
		SE_SYNC_AGENT_NAME,
		SE_SYSTEM_ENVIRONMENT_NAME,
		SE_SYSTEM_PROFILE_NAME,
		SE_SYSTEMTIME_NAME,
		SE_TAKE_OWNERSHIP_NAME,
		SE_TCB_NAME,
		SE_TIME_ZONE_NAME,
		SE_TRUSTED_CREDMAN_ACCESS_NAME,
		SE_UNDOCK_NAME,
		SE_UNSOLICITED_INPUT_NAME,
		NULL
	};
}

PCWCHAR WPRINTF_TYPES[] =
{
	L"%02x",		// WPRINTF_HEX_SHORT
	L"%02x ",		// WPRINTF_HEX_SPACE
	L"0x%02x, ",	// WPRINTF_HEX_C
	L"\\x%02x",		// WPRINTF_HEX_PYTHON
};

void toggle_privilege(const wchar_t* priv, BOOL status, BOOL* enabled);

int main(void)

{
    // match stringLiteral(unless(hasParent(initListExpr()))).bind('x')
    // excludes strings in list
    /*const KUHL_M_C kuhl_m_c_dpapi[] = {
	{0,			L"blob",		L"Describe a DPAPI blob, unprotect it with API or Masterkey"},
	{0,		L"protect",		L"Protect a data via a DPAPI call"},
	{0,	L"masterkey",	L"Describe a Masterkey file, unprotect each Masterkey (key depending)"},
	{0,		L"credhist",	L"Describe a Credhist file"}
    };


*/
	struct {PVOID LsaIRegisterNotification; PVOID LsaICancelNotification;} extractPkgFunctionTable;

	PWSTR szAttributes[] = {TEXT("schemaInfo"), NULL};
	LDAPControl deletedControl = {TEXT(szOID_ldapServer_show_deleted), 0};


   	f_NtMapViewOfSection lNtMapViewOfSection;
	HMODULE ntdll;

	if (!(ntdll = LoadLibrary(TEXT("ntdll"))))
	{
		return -1;
	}

	lNtMapViewOfSection = (f_NtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
    lNtMapViewOfSection(0,0,0,0,0,0,0,0,0,0);

	BOOL wasEnabled;
	toggle_privilege(SE_SECURITY_NAME, FALSE, &wasEnabled);
	toggle_privilege(L"", FALSE, &wasEnabled);
	toggle_privilege( L"AND SCOPE='%s:%s'", FALSE, &wasEnabled);

    return 0;
}
