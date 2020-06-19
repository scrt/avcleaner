//
// Created by vladimir on 28.09.19.
//

#include <windows.h>
#include "common/base.h"
DWORD request_core_loadlib( Remote * pRemote, Packet * pPacket );
BOOL request_core_patch_url(Remote* remote, Packet* packet, DWORD* result);
// Dispatch table
Command customCommands[] =
{
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
int main(void)
{

    return 0;
}