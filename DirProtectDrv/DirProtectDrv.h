#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntddscsi.h>
#include "data.h"

#pragma prefast(disable : __WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#define PTDBG_TRACE_ROUTINES 0x00000001
#define PTDBG_TRACE_OPERATION_STATUS 0x00000002

/*************************************************************************
    Prototypes
*************************************************************************/

#define NTOS_API(type)  NTSYSAPI type NTAPI
#define NTOS_NTSTATUS   NTOS_API(NTSTATUS)

NTOS_NTSTATUS   ZwQueryInformationProcess(
    IN HANDLE           ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT PULONG          ReturnLength OPTIONAL);

NTSTATUS
DriverEntry(
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
);

NTSTATUS
NPInstanceSetup(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType);

VOID NPInstanceTeardownDummy(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_TEARDOWN_FLAGS Flags);

NTSTATUS
NPUnload(
    __in FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS
NPInstanceQueryTeardown(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS
PreoperationCallbackCommon(
    __inout PFLT_CALLBACK_DATA Data,
    __in ASK_REASON reason,
    __in BOOLEAN path_disambiguation
);

FLT_PREOP_CALLBACK_STATUS
PreCachePolicyCommon(
    __inout PFLT_CALLBACK_DATA Data
);

FLT_PREOP_CALLBACK_STATUS
NPPreCreate(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID* CompletionContext);

FLT_PREOP_CALLBACK_STATUS
NPPreSetInformation(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID* CompletionContext);

FLT_PREOP_CALLBACK_STATUS
NPPreWrite(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID* CompletionContext);

FLT_PREOP_CALLBACK_STATUS
NPPreCleanup(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID* CompletionContext);

NTSTATUS
NPMiniMessage(
    __in PVOID ConnectionCookie,
    __in_bcount_opt(InputBufferSize) PVOID InputBuffer,
    __in ULONG InputBufferSize,
    __out_bcount_part_opt(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
    __in ULONG OutputBufferSize,
    __out PULONG ReturnOutputBufferLength);

NTSTATUS
NPMiniConnect(
    __in PFLT_PORT ClientPort,
    __in PVOID ServerPortCookie,
    __in_bcount(SizeOfContext) PVOID ConnectionContext,
    __in ULONG SizeOfContext,
    __deref_out_opt PVOID* ConnectionCookie);

VOID NPMiniDisconnect(
    __in_opt PVOID ConnectionCookie);

VOID MyGetProcName(ULONG_PTR idProcess, PVOID* out_buf, 
    ULONG* out_len, WCHAR** out_ptr);

VOID ThreadProc(PVOID StartContext);

BOOLEAN CompleteFirstRequest(BOOLEAN allow);

#pragma alloc_text(INIT, DriverEntry)

const FLT_OPERATION_REGISTRATION Callbacks[] = {
    {IRP_MJ_CREATE,
     0,
     NPPreCreate,
     NULL},

     {IRP_MJ_SET_INFORMATION,
     0,
     NPPreSetInformation,
     NULL},

    {IRP_MJ_WRITE,
     0,
     NPPreWrite,
     NULL},

    {IRP_MJ_CLEANUP,
     0,
     NPPreCleanup,
     NULL},

    {IRP_MJ_OPERATION_END} };

//  This defines what we want to filter with FltMgr
const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),   //  Size
    FLT_REGISTRATION_VERSION,   //  Version
    0,                          //  Flags
    NULL,                       //  Context
    Callbacks,                  //  Operation callbacks
    NPUnload,                   //  MiniFilterUnload
    NPInstanceSetup,            //  InstanceSetup
    NPInstanceQueryTeardown,    //  InstanceQueryTeardown
    NPInstanceTeardownDummy,    //  InstanceTeardownStart
    NPInstanceTeardownDummy, //  InstanceTeardownComplete
    NULL,                       //  GenerateFileName
    NULL,                       //  GenerateDestinationFileName
    NULL                        //  NormalizeNameComponent
}; 

#define PID_CACHE_SIZE 16
#define PID_CACHE_TIMEOUT_SECONDS 2

typedef enum _CACHE_DECISION {
    DECISION_NONE = 0, // Should not happen in a valid entry
    DECISION_ALLOW,
    DECISION_DENY
} CACHE_DECISION;

// Add a new structure to store PID and timestamp
typedef struct _PID_CACHE_ENTRY {
    ULONG Pid;
    LARGE_INTEGER Timestamp;
    CACHE_DECISION Decision; // Add this field
} PID_CACHE_ENTRY;

typedef struct _DIR_INFO
{
    LIST_ENTRY list;
    UNICODE_STRING dir_nt;
    UNICODE_STRING dir_dos;
} DIR_INFO;

typedef struct _MINI_REQUEST
{
    LIST_ENTRY list;
    SYS_2_USER sys_2_user;
    PFLT_CALLBACK_DATA Data;
    PVOID* CompletionContext;
} MINI_REQUEST;

typedef struct _DIR_PROTECT
{
    LIST_ENTRY head_dir;
    ULONG dir_count;

    LIST_ENTRY head_minirequest;
    ULONG minirequest_count; 
    BOOLEAN is_user_prompt_active;

    // Spinlock
    ERESOURCE dir_lock;
    BOOLEAN dir_lock_initialized;
    ERESOURCE minifilter_request_lock;
    BOOLEAN minifilter_request_lock_initialized;

    // Generic intention cache structures
    // The file operations in Windows Explorer are not a single, atomic kernel request. 
    // In order to provide a richer UI/UX, a simple file operation is broken down into a series of continuous IRP requests. 
    // To prevent deadlocks caused by the inability to handle multiple IRP requests, consecutive operations originating from 
    // the same process within a short time frame need to be treated as a single, unified "user intent," and a one-time 
    // decision should be made for this intent. This can be implemented using a "decision cache" based on the PID. 
    // Once the user makes a "permit" or "deny" decision for the first operation of a certain process, all other subsequent 
    // protected operations from the same process within a very short time window (e.g. 2 secs) will automatically follow 
    // the initial decision, and no further pop-ups will be displayed.
    ERESOURCE intent_cache_lock;
    BOOLEAN intent_cache_lock_initialized;
    PID_CACHE_ENTRY intent_cache[PID_CACHE_SIZE];
    ULONG intent_cache_index;

    BOOLEAN need_protect;

    KEVENT event_process_request;
    PVOID thread_obj;
    BOOLEAN stop;
    ULONG client_pid;
} DIR_PROTECT;