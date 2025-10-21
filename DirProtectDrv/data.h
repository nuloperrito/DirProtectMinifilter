#ifndef DATA_H
#define DATA_H

#define DIR_LENGTH 260
#define FILE_LENGTH 260
#define PROCESS_NAME_MAX_LEN 32

#define NPMINI_PORT_NAME L"\\DirProtectMiniPort"

typedef enum _COMMAND_TYPE
{
    ENUM_DIRINFO = 0,
    ENUM_START_PROTECT
} COMMAND_TYPE;

typedef struct _COMMAND_HEAD
{
    COMMAND_TYPE command_type;
} COMMAND_HEAD;

typedef struct _COMMAND_START_PROTECT
{
    COMMAND_HEAD command_head;
} COMMAND_START_PROTECT;

typedef struct _COMMAND_MESSAGE_DIR
{
    COMMAND_HEAD command_head;
    WCHAR protectdir_dos[DIR_LENGTH];
    WCHAR protectdir_nt[DIR_LENGTH];
} COMMAND_MESSAGE_DIR;

typedef enum _FILE_ACTION
{
    ACTION_CREATE,
    ACTION_SET_INFORMATION
} FILE_ACTION;

typedef enum _ASK_REASON
{
    REASON_DELETE_FILE = 1,
    REASON_DELETE_DIR,
    REASON_SET_DELETE_FLAG,
    REASON_CREATE_FILE,
    REASON_CREATE_DIR, 
    REASON_RENAME_OR_MOVE_FILE,
    REASON_RENAME_OR_MOVE_DIR,
    REASON_WRITE_FILE,
    REASON_NO_REASON
} ASK_REASON;

typedef struct _SYS_2_USER
{
    ULONG pid;
    WCHAR processname[PROCESS_NAME_MAX_LEN];
    FILE_ACTION file_action;
    ULONG access_mask;
    ASK_REASON ask_reason;
    WCHAR filename[FILE_LENGTH];
} SYS_2_USER;

typedef enum _REPLY_DATA
{
    REPLY_ALLOW = 1,
    REPLY_DENY
} REPLY_DATA;
typedef struct _USER_REPLY
{
    FILTER_REPLY_HEADER reply_header;
    REPLY_DATA reply_data;
} USER_REPLY;
#endif // !DATA_H