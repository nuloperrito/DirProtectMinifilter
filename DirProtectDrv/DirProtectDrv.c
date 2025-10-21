#include "DirProtectDrv.h"
//  Global variables

PFLT_FILTER gFilterHandle;
ULONG gTraceFlags = 0;

PFLT_FILTER gFilterHandle;
PFLT_PORT 	gServerPort;
PFLT_PORT 	gClientPort;

DIR_PROTECT global;

#define DIR_PROTECT_POOL_TAG	(ULONG)'PriD'
#define PROCESS_QUERY_INFORMATION (0x0400)

NTSTATUS
NPInstanceSetup(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    return STATUS_SUCCESS;
}


NTSTATUS
NPInstanceQueryTeardown(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    return STATUS_SUCCESS;
}


VOID
NPInstanceTeardownDummy(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry(
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uniString;		//for communication port name

    UNREFERENCED_PARAMETER(RegistryPath);

    //
    //  Register with FltMgr to tell it our callback routines
    RtlZeroMemory(&global, sizeof(DIR_PROTECT)); 
    global.is_user_prompt_active = FALSE;

    do
    {
        status = ExInitializeResourceLite(&global.dir_lock);
        if (!NT_SUCCESS(status)) {
            break;
        }
        global.dir_lock_initialized = TRUE; 
        
        status = ExInitializeResourceLite(&global.intent_cache_lock);
        if (!NT_SUCCESS(status)) {
            break;
        }
        global.intent_cache_lock_initialized = TRUE;
        RtlZeroMemory(global.intent_cache, sizeof(global.intent_cache));
        global.intent_cache_index = 0;

        status = ExInitializeResourceLite(&global.minifilter_request_lock);
        if (!NT_SUCCESS(status)) {
            break;
        }
        global.minifilter_request_lock_initialized = TRUE;

        HANDLE thread = NULL;
        status = PsCreateSystemThread(&thread, 0, NULL, NULL, NULL, ThreadProc, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }
        status = ObReferenceObjectByHandle(
            thread,
            THREAD_ALL_ACCESS,
            NULL,
            KernelMode,
            (PVOID*)&global.thread_obj,
            NULL
        );
        ZwClose(thread);
        thread = NULL;
        if (!NT_SUCCESS(status)) {
            break;
        }

        InitializeListHead(&global.head_dir);
        InitializeListHead(&global.head_minirequest);

        KeInitializeEvent(&global.event_process_request, SynchronizationEvent, FALSE);

        status = FltRegisterFilter(DriverObject,
            &FilterRegistration,
            &gFilterHandle);

        if (!NT_SUCCESS(status)) {
            break;
        }

        status = FltStartFiltering(gFilterHandle);

        if (!NT_SUCCESS(status)) {
            break;
        }

        status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
        if (!NT_SUCCESS(status)) {
            break;
        }

        RtlInitUnicodeString(&uniString, NPMINI_PORT_NAME);

        InitializeObjectAttributes(&oa,
            &uniString,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
            NULL,
            sd);

        status = FltCreateCommunicationPort(gFilterHandle,
            &gServerPort,
            &oa,
            NULL,
            NPMiniConnect,
            NPMiniDisconnect,
            NPMiniMessage,
            1);

        if (!NT_SUCCESS(status)) {
            break;
        }

    } while (0);
    if (NULL != sd)
    {
        FltFreeSecurityDescriptor(sd);
        sd = NULL;
    }

    if (!NT_SUCCESS(status)) {

        if (NULL != gServerPort) {
            FltCloseCommunicationPort(gServerPort);
        }

        if (NULL != gFilterHandle) {
            FltUnregisterFilter(gFilterHandle);
        }
        if (global.dir_lock_initialized)
        {
            global.dir_lock_initialized = FALSE;
            ExDeleteResourceLite(&global.dir_lock);
        }
        if (global.minifilter_request_lock_initialized)
        {
            global.minifilter_request_lock_initialized = FALSE;
            ExDeleteResourceLite(&global.minifilter_request_lock);
        }
        if (global.intent_cache_lock_initialized)
        {
            global.intent_cache_lock_initialized = FALSE;
            ExDeleteResourceLite(&global.intent_cache_lock);
        }
        if (NULL != global.thread_obj)
        {
            ObDereferenceObject(global.thread_obj);
            global.thread_obj = NULL;
        }
    }

    return status;
}

NTSTATUS
NPUnload(
    __in FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    NTSTATUS status = STATUS_SUCCESS;

    if (NULL != global.thread_obj)
    {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -30 * 10 * 1000 * 1000; // 30s

        global.stop = TRUE;
        KeSetEvent(&global.event_process_request, IO_NO_INCREMENT, FALSE);
        status = KeWaitForSingleObject(global.thread_obj, Executive, KernelMode, FALSE, &timeout);
        if (STATUS_TIMEOUT == status)
        {
            DbgPrint("Warning: Worker thread did not terminate properly (Status: 0x%X)\n", status);
        }
        ObDereferenceObject(global.thread_obj);
        global.thread_obj = NULL;
    }

    if (global.dir_lock_initialized)
    {
        global.dir_lock_initialized = FALSE;
        ExDeleteResourceLite(&global.dir_lock);
    }
    if (global.minifilter_request_lock_initialized)
    {
        global.minifilter_request_lock_initialized = FALSE;
        ExDeleteResourceLite(&global.minifilter_request_lock);
    }
    if (global.intent_cache_lock_initialized)
    {
        global.intent_cache_lock_initialized = FALSE;
        ExDeleteResourceLite(&global.intent_cache_lock);
    }

    FltCloseCommunicationPort(gServerPort);

    FltUnregisterFilter(gFilterHandle);

    return STATUS_SUCCESS;
}

/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
VOID MyGetProcName(ULONG_PTR idProcess, PVOID* out_buf, ULONG* out_len, WCHAR** out_ptr)
{
    NTSTATUS status;
    HANDLE handle = NULL;
    PUNICODE_STRING imageName = NULL;
    ULONG requiredLen = 0;

    *out_buf = NULL;
    *out_len = 0;
    *out_ptr = NULL;

    if (!idProcess)
    {
        return;
    }

    CLIENT_ID cid = { (HANDLE)idProcess, 0 };
    OBJECT_ATTRIBUTES objattrs;
    InitializeObjectAttributes(&objattrs, NULL, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenProcess(&handle, PROCESS_QUERY_INFORMATION, &objattrs, &cid);
    if (!NT_SUCCESS(status))
    {
        return;
    }

    status = ZwQueryInformationProcess(handle, ProcessImageFileName, NULL, 0, &requiredLen);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
    {
        goto cleanup;
    }

    imageName = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, requiredLen, DIR_PROTECT_POOL_TAG);
    if (!imageName)
    {
        goto cleanup;
    }

    status = ZwQueryInformationProcess(handle, ProcessImageFileName, imageName, requiredLen, &requiredLen);
    if (!NT_SUCCESS(status) || imageName->Buffer == NULL || imageName->Length == 0)
    {
        ExFreePoolWithTag(imageName, DIR_PROTECT_POOL_TAG);
        goto cleanup;
    }

    imageName->Buffer[imageName->Length / sizeof(WCHAR)] = L'\0';

    WCHAR* fileNamePtr = wcsrchr(imageName->Buffer, L'\\');

    *out_ptr = fileNamePtr ? (fileNamePtr + 1) : imageName->Buffer;

    *out_buf = imageName;
    *out_len = requiredLen;

cleanup:
    if (handle)
    {
        ZwClose(handle);
    }
}

BOOLEAN CompleteFirstRequest(BOOLEAN allow)
{
    MINI_REQUEST* request = NULL;
    if (ExAcquireResourceExclusiveLite(&global.minifilter_request_lock, TRUE))
    {
        __try
        {
            if (0 != global.minirequest_count)
            {
                PLIST_ENTRY entry = RemoveHeadList(&global.head_minirequest);
                --global.minirequest_count;
                request = CONTAINING_RECORD(entry, MINI_REQUEST, list);
            }
        }
        __finally
        {
            ExReleaseResourceLite(&global.minifilter_request_lock);
        }
    }
    if (NULL != request)
    {
        if (allow)
        {
            FltCompletePendedPreOperation(request->Data, FLT_PREOP_SUCCESS_NO_CALLBACK, NULL);
        }
        else
        {
            request->Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            request->Data->IoStatus.Information = 0;
            FltCompletePendedPreOperation(request->Data, FLT_PREOP_COMPLETE, NULL);
        }
        ExFreePoolWithTag(request, DIR_PROTECT_POOL_TAG);

        request = NULL; 
        global.is_user_prompt_active = FALSE;
        return TRUE;
    }
    global.is_user_prompt_active = FALSE;
    return FALSE;
}

VOID ThreadProc(PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);

    do
    {
        SYS_2_USER sys_2_user = { 0 };
        BOOLEAN have_data = FALSE;
        if (global.minifilter_request_lock_initialized && ExAcquireResourceSharedLite(&global.minifilter_request_lock, TRUE))
        {
            __try
            {
                PLIST_ENTRY entry = global.head_minirequest.Flink;

                while (entry != &global.head_minirequest)
                {
                    MINI_REQUEST* request = CONTAINING_RECORD(entry, MINI_REQUEST, list);
                    sys_2_user = request->sys_2_user;
                    have_data = TRUE;
                    break;
                }
            }
            __finally
            {
                ExReleaseResourceLite(&global.minifilter_request_lock);
            }
        }
        if (have_data)
        {
            union
            {
                USER_REPLY recv;
                REPLY_DATA data;
            }reply;

            ULONG reply_len = sizeof(FILTER_REPLY_HEADER) + sizeof(REPLY_DATA);
            LARGE_INTEGER timeout;
            timeout.QuadPart = -70 * 1000 * 1000 * 10; // 70s

            NTSTATUS status = FltSendMessage(gFilterHandle, &gClientPort, &sys_2_user, sizeof(SYS_2_USER), &reply.recv, &reply_len, &timeout);

            BOOLEAN allow = NT_SUCCESS(status) && REPLY_ALLOW == reply.data;

            // Cache the decision (both allow and deny)
            if (ExAcquireResourceExclusiveLite(&global.intent_cache_lock, TRUE))
            {
                LARGE_INTEGER currentTime;
                KeQuerySystemTime(&currentTime);

                global.intent_cache[global.intent_cache_index].Pid = sys_2_user.pid;
                global.intent_cache[global.intent_cache_index].Timestamp = currentTime;
                global.intent_cache[global.intent_cache_index].Decision = allow ? DECISION_ALLOW : DECISION_DENY;

                // Use loop queue for cache
                global.intent_cache_index = (global.intent_cache_index + 1) % PID_CACHE_SIZE;

                ExReleaseResourceLite(&global.intent_cache_lock);
            }

            CompleteFirstRequest(allow); // This now only completes the pended IRP
        }
        else
        {
            KeWaitForSingleObject(&global.event_process_request, Executive, KernelMode, FALSE, NULL);
        }
    } while (!global.stop);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

FLT_PREOP_CALLBACK_STATUS
PreoperationCallbackCommon(
    __inout PFLT_CALLBACK_DATA Data,
    __in ASK_REASON reason,
    __in BOOLEAN path_disambiguation
) 
{
    FLT_PREOP_CALLBACK_STATUS call_status = FLT_PREOP_SUCCESS_NO_CALLBACK;
    BOOLEAN found = FALSE;
    MINI_REQUEST* mini_request = NULL;
    SYS_2_USER* sys_2_user = NULL;
    void* nbuf = NULL;
    ULONG nlen = 0;
    WCHAR* nptr = NULL;
    ULONG pid = FltGetRequestorProcessId(Data);

    PFLT_FILE_NAME_INFORMATION name_info = NULL;
    NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name_info);

    if (!NT_SUCCESS(status))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (ExAcquireResourceSharedLite(&global.dir_lock, TRUE))
    {
        __try
        {
            PLIST_ENTRY entry = global.head_dir.Flink;
            while (entry != &global.head_dir)
            {
                DIR_INFO* dir_info = CONTAINING_RECORD(entry, DIR_INFO, list);

                if (RtlPrefixUnicodeString(&dir_info->dir_nt, &name_info->Name, TRUE))
                {
                    if (path_disambiguation) {
                        // This logic is crucial for distinguishing a preparatory "open"
                        // on the directory itself from a genuine "create" of a child item.

                        // If the target path is identical to the protected path,
                        // this is a preparatory IRP (e.g., opening C:\protected before copying a file into it).
                        // This is not the action we need to prompt for. We ignore it and wait for the
                        // subsequent IRP that targets the new file/folder inside.
                        if (name_info->Name.Length == dir_info->dir_nt.Length)
                        {
                            entry = entry->Flink; // Move to the next protected directory in the list
                            continue;             // Skip to the next iteration of the loop
                        }

                        // Sanity check: ensure the child path is correctly formed (e.g., C:\protected\file, not C:\protected-file)
                        // This check was already implicitly part of your original logic and is good practice.
                        if (name_info->Name.Length > dir_info->dir_nt.Length &&
                            name_info->Name.Buffer[dir_info->dir_nt.Length / sizeof(WCHAR)] != L'\\')
                        {
                            entry = entry->Flink;
                            continue;
                        }
                    }

                    found = TRUE;
                    // If a pop-up window already exists, reject it directly to prevent request accumulation
                    if (global.is_user_prompt_active)
                    {
                        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                        Data->IoStatus.Information = 0;
                        call_status = FLT_PREOP_COMPLETE;
                        break;
                    }

                    MyGetProcName((ULONG_PTR)pid, &nbuf, &nlen, &nptr);
                    if (NULL == nbuf)
                    {
                        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                        Data->IoStatus.Information = 0;
                        call_status = FLT_PREOP_COMPLETE;
                        break;
                    }

                    mini_request = ExAllocatePoolWithTag(NonPagedPool, sizeof(MINI_REQUEST), DIR_PROTECT_POOL_TAG);
                    if (NULL == mini_request)
                    {
                        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                        Data->IoStatus.Information = 0;
                        call_status = FLT_PREOP_COMPLETE;
                        break;
                    }
                    RtlZeroMemory(mini_request, sizeof(MINI_REQUEST));
                    sys_2_user = &mini_request->sys_2_user;
                    sys_2_user->ask_reason = reason;
                    size_t dos_path_prefix_len = dir_info->dir_dos.Length;
                    size_t nt_path_prefix_len = dir_info->dir_nt.Length;
                    size_t remaining_path_len = name_info->Name.Length - nt_path_prefix_len;
                    size_t total_dos_path_len = dos_path_prefix_len + remaining_path_len;

                    if (total_dos_path_len < sizeof(sys_2_user->filename)) {
                        RtlCopyMemory(sys_2_user->filename, dir_info->dir_dos.Buffer, dos_path_prefix_len);
                        if (remaining_path_len > 0) {
                            RtlCopyMemory((PCHAR)sys_2_user->filename + dos_path_prefix_len, (PCHAR)name_info->Name.Buffer + nt_path_prefix_len, remaining_path_len);
                        }
                        sys_2_user->filename[total_dos_path_len / sizeof(WCHAR)] = L'\0';
                    }
                    break;
                }
                entry = entry->Flink;
            }
        }
        __finally
        {
            ExReleaseResourceLite(&global.dir_lock);
        }
    }

    if (found && mini_request != NULL && sys_2_user != NULL)
    {
        sys_2_user->pid = pid;

        wcsncpy_s(sys_2_user->processname, ARRAYSIZE(sys_2_user->processname) - 1, nptr, _TRUNCATE);

        mini_request->Data = Data;

        if (ExAcquireResourceExclusiveLite(&global.minifilter_request_lock, TRUE))
        {
            // Set the flag to TRUE before pending the operation.
            global.is_user_prompt_active = TRUE;

            // insert data
            InsertTailList(&global.head_minirequest, &mini_request->list);
            ++global.minirequest_count;
            ExReleaseResourceLite(&global.minifilter_request_lock);
            // wake system thread
            KeSetEvent(&global.event_process_request, IO_NO_INCREMENT, FALSE);
            call_status = FLT_PREOP_PENDING;
        }
    }

    if (NULL != name_info)
    {
        FltReleaseFileNameInformation(name_info);
        name_info = NULL;
    }

    if (FLT_PREOP_PENDING != call_status)
    {
        if (NULL != mini_request)
        {
            ExFreePool(mini_request);
            mini_request = NULL;
        }
    }
    if (NULL != nbuf)
    {
        ExFreePool(nbuf);
        nbuf = NULL;
    }

    return call_status;
}

FLT_PREOP_CALLBACK_STATUS
PreCachePolicyCommon(
    __inout PFLT_CALLBACK_DATA Data
) {
    ULONG pid = FltGetRequestorProcessId(Data);
    if (KernelMode == Data->RequestorMode || !global.need_protect || pid == global.client_pid)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (ExAcquireResourceSharedLite(&global.intent_cache_lock, TRUE))
    {
        LARGE_INTEGER currentTime;
        LARGE_INTEGER timeout;
        // Timeout is negative, representing a duration from the past
        timeout.QuadPart = -((LONGLONG)PID_CACHE_TIMEOUT_SECONDS * 10 * 1000 * 1000);
        KeQuerySystemTime(&currentTime);

        for (int i = 0; i < PID_CACHE_SIZE; ++i)
        {
            if (global.intent_cache[i].Pid == pid)
            {
                // Check if the timestamp has expired. 
                // A larger timestamp is more recent.
                if ((currentTime.QuadPart - global.intent_cache[i].Timestamp.QuadPart) < -timeout.QuadPart)
                {
                    CACHE_DECISION decision = global.intent_cache[i].Decision;
                    ExReleaseResourceLite(&global.intent_cache_lock);

                    if (decision == DECISION_DENY)
                    {
                        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                        Data->IoStatus.Information = 0;
                        return FLT_PREOP_COMPLETE;
                    }
                    else if (decision == DECISION_ALLOW)
                    {
                        return FLT_PREOP_SUCCESS_NO_CALLBACK;
                    }
                    // If decision is somehow NONE, fall through to prompt again.
                }
            }
        }
        ExReleaseResourceLite(&global.intent_cache_lock);
    }
    return -1;
}

FLT_PREOP_CALLBACK_STATUS
NPPreCreate(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID* CompletionContext
)
{

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    FLT_PREOP_CALLBACK_STATUS cb_status = PreCachePolicyCommon(Data);
    if (cb_status >= 0) return cb_status;

    ULONG create_disposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF; // high 8 bit
    ULONG create_options = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;       // low 24 bit

    ASK_REASON reason = REASON_NO_REASON;

    // First check for deletion intent via create options.
    if (create_options & FILE_DELETE_ON_CLOSE)
    {
        reason = REASON_SET_DELETE_FLAG;
    }
    // Check for operations that are clearly modifications/writes to existing files.
    // FILE_OPEN_IF is often used for "safe save" mechanisms and should be treated as a write.
    else if (create_disposition == FILE_SUPERSEDE ||
        create_disposition == FILE_OVERWRITE_IF ||
        create_disposition == FILE_OVERWRITE ||
        create_disposition == FILE_OPEN_IF)
    {
        reason = REASON_WRITE_FILE;
    }
    // 3. Check for pure creation of a new entity.
    else if (create_disposition == FILE_CREATE)
    {
        if (create_options & FILE_DIRECTORY_FILE)
        {
            reason = REASON_CREATE_DIR;
        }
        else
        {
            reason = REASON_CREATE_FILE;
        }
    }

    // If no action we care about is found, let it pass.
    if (reason == REASON_NO_REASON)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return PreoperationCallbackCommon(Data, reason, TRUE);
}

FLT_PREOP_CALLBACK_STATUS
NPPreSetInformation(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    FLT_PREOP_CALLBACK_STATUS cb_status = PreCachePolicyCommon(Data);
    if (cb_status >= 0) return cb_status;

    ASK_REASON reason = REASON_NO_REASON;

    // Determine the specific operation based on FileInformationClass
    switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass)
    {
        // delete
    case FileDispositionInformation:
    case FileDispositionInformationEx:
    {
        PFILE_DISPOSITION_INFORMATION info = (PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        if (info->DeleteFile)
        {
            BOOLEAN isDirectory = FALSE;
            NTSTATUS status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDirectory);
            if (NT_SUCCESS(status)) {
                if (isDirectory) {
                    reason = REASON_DELETE_DIR;
                }
                else {
                    reason = REASON_DELETE_FILE;
                }
            }
            else reason = REASON_SET_DELETE_FLAG; // fall back to a generic delete flag
        }
        break;
    }
    // rename or move
    case FileRenameInformation:
    {
        PFLT_FILE_NAME_INFORMATION srcNameInfo = NULL;
        PFLT_FILE_NAME_INFORMATION destNameInfo = NULL;
        BOOLEAN isSourceProtected = FALSE;
        BOOLEAN isDestinationProtected = FALSE;
        NTSTATUS status;

        // Get the destination path first
        PFILE_RENAME_INFORMATION renameInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        status = FltGetDestinationFileNameInformation(Data->Iopb->TargetInstance,
            Data->Iopb->TargetFileObject,
            renameInfo->RootDirectory,
            renameInfo->FileName,
            renameInfo->FileNameLength,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &destNameInfo);

        if (!NT_SUCCESS(status)) {
            // If we can't get destination, deny for safety as it might be a move into a protected area.
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }

        // Now get the source path
        status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &srcNameInfo);
        if (!NT_SUCCESS(status)) {
            FltReleaseFileNameInformation(destNameInfo);
            // If we can't get source, also deny for safety.
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }

        DIR_INFO* protectedDirInfo = NULL; // To store the matched protected directory info
        PFLT_FILE_NAME_INFORMATION finalNameInfo = NULL; // To store the path we'll show to the user

        // Now, check if EITHER the source OR destination path is inside a protected directory.
        if (ExAcquireResourceSharedLite(&global.dir_lock, TRUE))
        {
            __try
            {
                PLIST_ENTRY entry = global.head_dir.Flink;
                while (entry != &global.head_dir)
                {
                    DIR_INFO* dir_info = CONTAINING_RECORD(entry, DIR_INFO, list);

                    if (RtlPrefixUnicodeString(&dir_info->dir_nt, &destNameInfo->Name, TRUE)) {
                        isDestinationProtected = TRUE;
                    }

                    if (RtlPrefixUnicodeString(&dir_info->dir_nt, &srcNameInfo->Name, TRUE)) {
                        isSourceProtected = TRUE;
                    }

                    if (isSourceProtected || isDestinationProtected) {
                        // We found a match. Store the relevant info.
                        // Prioritize destination path for user display.
                        if (isDestinationProtected) {
                            finalNameInfo = destNameInfo;
                            protectedDirInfo = dir_info;
                        }
                        else { // otherwise use source
                            finalNameInfo = srcNameInfo;
                            protectedDirInfo = dir_info;
                        }
                        break; // Exit loop once a match is found
                    }

                    entry = entry->Flink;
                }
            }
            __finally
            {
                ExReleaseResourceLite(&global.dir_lock);
            }
        }

        // If either path is protected, we need to intercept this operation.
        if (isSourceProtected || isDestinationProtected)
        {
            BOOLEAN isDirectory = FALSE;
            status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDirectory);
            if (NT_SUCCESS(status)) {
                reason = isDirectory ? REASON_RENAME_OR_MOVE_DIR : REASON_RENAME_OR_MOVE_FILE;
            }
            else {
                reason = REASON_RENAME_OR_MOVE_FILE; // Fallback
            }

            // If a pop-up window already exists, reject it directly
            if (global.is_user_prompt_active)
            {
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                cb_status = FLT_PREOP_COMPLETE;
            }
            else
            {
                // This logic is moved from PreoperationCallbackCommon
                MINI_REQUEST* mini_request = NULL;
                SYS_2_USER* sys_2_user = NULL;
                void* nbuf = NULL;
                ULONG nlen = 0;
                WCHAR* nptr = NULL;
                ULONG pid = FltGetRequestorProcessId(Data);

                MyGetProcName((ULONG_PTR)pid, &nbuf, &nlen, &nptr);
                if (NULL == nbuf)
                {
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    Data->IoStatus.Information = 0;
                    cb_status = FLT_PREOP_COMPLETE;
                }
                else
                {
                    mini_request = ExAllocatePoolWithTag(NonPagedPool, sizeof(MINI_REQUEST), DIR_PROTECT_POOL_TAG);
                    if (NULL == mini_request)
                    {
                        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                        Data->IoStatus.Information = 0;
                        cb_status = FLT_PREOP_COMPLETE;
                    }
                    else
                    {
                        RtlZeroMemory(mini_request, sizeof(MINI_REQUEST));
                        sys_2_user = &mini_request->sys_2_user;
                        sys_2_user->ask_reason = reason;
                        sys_2_user->pid = pid;
                        wcsncpy_s(sys_2_user->processname, ARRAYSIZE(sys_2_user->processname) - 1, nptr, _TRUNCATE);

                        // Construct DOS path for UI from NT path
                        size_t dos_path_prefix_len = protectedDirInfo->dir_dos.Length;
                        size_t nt_path_prefix_len = protectedDirInfo->dir_nt.Length;
                        size_t remaining_path_len = finalNameInfo->Name.Length - nt_path_prefix_len;
                        size_t total_dos_path_len = dos_path_prefix_len + remaining_path_len;

                        if (total_dos_path_len < sizeof(sys_2_user->filename)) {
                            RtlCopyMemory(sys_2_user->filename, protectedDirInfo->dir_dos.Buffer, dos_path_prefix_len);
                            if (remaining_path_len > 0) {
                                RtlCopyMemory((PCHAR)sys_2_user->filename + dos_path_prefix_len, (PCHAR)finalNameInfo->Name.Buffer + nt_path_prefix_len, remaining_path_len);
                            }
                            sys_2_user->filename[total_dos_path_len / sizeof(WCHAR)] = L'\0';
                        }

                        mini_request->Data = Data;

                        if (ExAcquireResourceExclusiveLite(&global.minifilter_request_lock, TRUE))
                        {
                            global.is_user_prompt_active = TRUE;
                            InsertTailList(&global.head_minirequest, &mini_request->list);
                            ++global.minirequest_count;
                            ExReleaseResourceLite(&global.minifilter_request_lock);
                            KeSetEvent(&global.event_process_request, IO_NO_INCREMENT, FALSE);
                            cb_status = FLT_PREOP_PENDING;
                        }
                        else {
                            ExFreePoolWithTag(mini_request, DIR_PROTECT_POOL_TAG);
                            mini_request = NULL;
                        }
                    }
                }
                if (nbuf) {
                    ExFreePool(nbuf);
                }
            }
        }

        // Cleanup the name info structures
        if (srcNameInfo) FltReleaseFileNameInformation(srcNameInfo);
        if (destNameInfo) FltReleaseFileNameInformation(destNameInfo);

        if (cb_status != FLT_PREOP_PENDING) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        return cb_status; // Return directly, bypassing the common handler call.
    }
    default:
        // For other SetInformation types, do not intercept yet
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (reason == REASON_NO_REASON)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return PreoperationCallbackCommon(Data, reason, FALSE);
}

FLT_PREOP_CALLBACK_STATUS
NPPreWrite(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    FLT_PREOP_CALLBACK_STATUS cb_status = PreCachePolicyCommon(Data);
    if (cb_status >= 0) return cb_status;

    // For write operations, the reason is clear
    ASK_REASON reason = REASON_WRITE_FILE;

    return PreoperationCallbackCommon(Data, reason, FALSE);
}

FLT_PREOP_CALLBACK_STATUS
NPPreCleanup(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    FLT_PREOP_CALLBACK_STATUS cb_status = PreCachePolicyCommon(Data);
    if (cb_status >= 0) return cb_status;

    // Check if the FO_DELETE_ON_CLOSE flag is set on the file object.
    // This indicates a deferred delete operation happening at cleanup time.
    if (FlagOn(FltObjects->FileObject->Flags, FO_DELETE_ON_CLOSE))
    {
        BOOLEAN isDirectory = FALSE;
        ASK_REASON reason;

        FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDirectory);

        if (isDirectory)
        {
            reason = REASON_DELETE_DIR;
        }
        else
        {
            reason = REASON_DELETE_FILE;
        }

        // Use the common callback to send the request to the user application.
        // Path disambiguation is not needed here as we are operating on an existing object.
        return PreoperationCallbackCommon(Data, reason, FALSE);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// user application connect
NTSTATUS
NPMiniConnect(
    __in PFLT_PORT ClientPort,
    __in PVOID ServerPortCookie,
    __in_bcount(SizeOfContext) PVOID ConnectionContext,
    __in ULONG SizeOfContext,
    __deref_out_opt PVOID* ConnectionCookie
)
{
    DbgPrint("[mini-filter] DirProtectMiniConnect");

    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);

    ASSERT(gClientPort == NULL);
    gClientPort = ClientPort;

    global.client_pid = (ULONG)(ULONG64)PsGetCurrentProcessId();
    return STATUS_SUCCESS;
}

//user application Disconect
VOID
NPMiniDisconnect(
    __in_opt PVOID ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    DbgPrint("[mini-filter] DirProtectMiniDisconnect");

    //  Close our handle
    FltCloseClientPort(gFilterHandle, &gClientPort);
    gClientPort = NULL;

    global.client_pid = 0;

    // 1. First, deny all pending requests in the queue.
    //    This ensures that any operation waiting for a user reply is properly denied
    //    before we turn off protection.
    while (CompleteFirstRequest(FALSE));

    global.need_protect = FALSE;

    //clear dir
    if (ExAcquireResourceExclusiveLite(&global.dir_lock, TRUE))
    {
        while (global.dir_count > 0)
        {
            PLIST_ENTRY entry = RemoveHeadList(&global.head_dir);
            --global.dir_count;
            DIR_INFO* dir_info = CONTAINING_RECORD(entry, DIR_INFO, list);
            if (NULL != dir_info)
            {
                if (NULL != dir_info->dir_dos.Buffer)
                {
                    ExFreePool(dir_info->dir_dos.Buffer);
                    dir_info->dir_dos.Buffer = NULL;
                }
                if (NULL != dir_info->dir_nt.Buffer)
                {
                    ExFreePool(dir_info->dir_nt.Buffer);
                    dir_info->dir_nt.Buffer = NULL;
                }
                ExFreePool(dir_info);
                dir_info = NULL;
            }
        }
        ExReleaseResourceLite(&global.dir_lock);
    }

}

NTSTATUS
NPMiniMessage(
    __in PVOID ConnectionCookie,
    __in_bcount_opt(InputBufferSize) PVOID InputBuffer,
    __in ULONG InputBufferSize,
    __out_bcount_part_opt(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
    __in ULONG OutputBufferSize,
    __out PULONG ReturnOutputBufferLength
)
{
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferSize);

    UNREFERENCED_PARAMETER(ReturnOutputBufferLength);
    UNREFERENCED_PARAMETER(ConnectionCookie);
    UNREFERENCED_PARAMETER(OutputBufferSize);
    UNREFERENCED_PARAMETER(OutputBuffer);

    DbgPrint("[mini-filter] DirProtectMiniMessage");

    COMMAND_HEAD* head = (COMMAND_HEAD*)InputBuffer;
    WCHAR* dir_dos = NULL;
    WCHAR* dir_nt = NULL;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    DIR_INFO* info = NULL;
    do
    {
        if (NULL == head)
        {
            break;
        }
        __try
        {
            if (ENUM_DIRINFO == head->command_type)
            {
                if (InputBufferSize == sizeof(COMMAND_MESSAGE_DIR))
                {
                    COMMAND_MESSAGE_DIR* dir = (COMMAND_MESSAGE_DIR*)InputBuffer;
                    if (NULL == dir || L'\0' == dir->protectdir_dos[0] || L'\0' == dir->protectdir_dos[0])
                    {
                        break;
                    }

                    size_t dos_len = wcslen(dir->protectdir_dos) * sizeof(WCHAR);
                    size_t nt_len = wcslen(dir->protectdir_nt) * sizeof(WCHAR);
                    if (dos_len >= sizeof(dir->protectdir_dos) || nt_len >= sizeof(dir->protectdir_nt))
                    {
                        status = STATUS_INVALID_PARAMETER;
                        break;
                    }

                    dir_dos = ExAllocatePoolWithTag(NonPagedPool, dos_len, DIR_PROTECT_POOL_TAG);
                    if (NULL != dir_dos)
                    {
                        dir_nt = ExAllocatePoolWithTag(NonPagedPool, nt_len, DIR_PROTECT_POOL_TAG);
                    }
                    if (NULL != dir_dos && NULL != dir_nt)
                    {
                        info = ExAllocatePoolWithTag(NonPagedPool, sizeof(DIR_INFO), DIR_PROTECT_POOL_TAG);
                        if (NULL != info)
                        {
                            memcpy(dir_dos, dir->protectdir_dos, dos_len);
                            info->dir_dos.Buffer = dir_dos;
                            info->dir_dos.Length = info->dir_dos.MaximumLength = (USHORT)dos_len;

                            memcpy(dir_nt, dir->protectdir_nt, nt_len);
                            info->dir_nt.Buffer = dir_nt;
                            info->dir_nt.Length = info->dir_nt.MaximumLength = (USHORT)nt_len;

                            if (ExAcquireResourceExclusiveLite(&global.dir_lock, TRUE))
                            {
                                InsertTailList(&global.head_dir, &info->list);
                                ++global.dir_count;
                                ExReleaseResourceLite(&global.dir_lock);
                                status = STATUS_SUCCESS;
                            }
                        }
                        else
                        {
                            status = STATUS_INSUFFICIENT_RESOURCES;
                        }
                    }
                    else
                    {
                        status = STATUS_INSUFFICIENT_RESOURCES;
                    }
                }
            }
            else if (ENUM_START_PROTECT == head->command_type)
            {
                global.need_protect = TRUE;
                status = STATUS_SUCCESS;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = STATUS_INVALID_PARAMETER;
        }

    } while (0);

    if (!NT_SUCCESS(status))
    {
        if (NULL != dir_dos)
        {
            ExFreePool(dir_dos);
            dir_dos = NULL;
        }
        if (NULL != dir_nt)
        {
            ExFreePool(dir_nt);
            dir_nt = NULL;
        }
        if (NULL != info)
        {
            ExFreePool(info);
            info = NULL;
        }
    }
    return status;
}
