#include <fltKernel.h>
#include <ntstrsafe.h>

#include "../include/aegis_file_minifilter_protocol.h"

PFLT_FILTER gFilterHandle = NULL;
PFLT_PORT gServerPort = NULL;
PFLT_PORT gClientPort = NULL;
FAST_MUTEX gFileJournalLock;
AEGIS_FILE_EVENT_RECORD gFileJournal[AEGIS_FILE_MINIFILTER_QUEUE_CAPACITY];
ULONG gFileJournalHead = 0;
ULONG gFileJournalCount = 0;
ULONG gFileNextSequence = 1;
FAST_MUTEX gProtectedPathLock;
WCHAR gProtectedPaths[AEGIS_FILE_PROTECTED_PATH_CAPACITY][AEGIS_FILE_MAX_PATH_CHARS];
ULONG gProtectedPathCount = 0;

static VOID AegisFileJournalPush(_In_ const AEGIS_FILE_EVENT_RECORD* record);
static VOID AegisCopyUnicodeString(
    _Out_writes_(destination_count) PWCHAR destination,
    _In_ SIZE_T destination_count,
    _In_opt_ PCUNICODE_STRING source
);
static VOID AegisRecordFileEvent(
    _In_ PCWSTR operation,
    _Inout_ PFLT_CALLBACK_DATA data
);
static ULONG AegisProtectedPathCountUnlocked(VOID);
static VOID AegisClearProtectedPaths(VOID);
static NTSTATUS AegisAddProtectedPath(_In_ PCWSTR path);
static BOOLEAN AegisPathMatchesProtectedPrefix(_In_ PCUNICODE_STRING path);
static BOOLEAN AegisCreateHasWriteIntent(_In_ PFLT_CALLBACK_DATA Data);
static BOOLEAN AegisIsProtectedFileOperation(_In_ PFLT_CALLBACK_DATA Data);
static FLT_PREOP_CALLBACK_STATUS AegisDenyFileOperation(
    _In_ PCWSTR operation,
    _Inout_ PFLT_CALLBACK_DATA Data
);

NTSTATUS
AegisFilePortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie
);

VOID
AegisFilePortDisconnect(
    _In_opt_ PVOID ConnectionCookie
);

NTSTATUS
AegisFilePortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
);

FLT_PREOP_CALLBACK_STATUS
AegisFilePreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
AegisFilePreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
AegisFilePreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

NTSTATUS
AegisFileUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, AegisFilePreCreate, NULL },
    { IRP_MJ_WRITE, 0, AegisFilePreWrite, NULL },
    { IRP_MJ_SET_INFORMATION, 0, AegisFilePreSetInformation, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    AegisFileUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

static ULONG AegisFileJournalOldestSequenceUnlocked(VOID) {
    if (gFileJournalCount == 0) {
        return 0;
    }

    return gFileJournal[gFileJournalHead].Sequence;
}

static ULONG AegisFileJournalCurrentSequenceUnlocked(VOID) {
    if (gFileNextSequence == 0) {
        return 0;
    }

    return gFileNextSequence - 1;
}

static ULONG AegisProtectedPathCountUnlocked(VOID) {
    return gProtectedPathCount;
}

static VOID AegisCopyUnicodeString(
    _Out_writes_(destination_count) PWCHAR destination,
    _In_ SIZE_T destination_count,
    _In_opt_ PCUNICODE_STRING source
) {
    SIZE_T copy_chars = 0;

    if (destination == NULL || destination_count == 0) {
        return;
    }

    RtlZeroMemory(destination, destination_count * sizeof(WCHAR));
    if (source == NULL || source->Buffer == NULL || source->Length == 0) {
        return;
    }

    copy_chars = source->Length / sizeof(WCHAR);
    if (copy_chars >= destination_count) {
        copy_chars = destination_count - 1;
    }

    if (copy_chars > 0) {
        RtlCopyMemory(destination, source->Buffer, copy_chars * sizeof(WCHAR));
    }
    destination[copy_chars] = UNICODE_NULL;
}

static VOID AegisFileJournalPush(_In_ const AEGIS_FILE_EVENT_RECORD* record) {
    ULONG slot;

    ExAcquireFastMutex(&gFileJournalLock);
    if (gFileJournalCount == AEGIS_FILE_MINIFILTER_QUEUE_CAPACITY) {
        slot = gFileJournalHead;
        gFileJournalHead = (gFileJournalHead + 1) % AEGIS_FILE_MINIFILTER_QUEUE_CAPACITY;
    } else {
        slot = (gFileJournalHead + gFileJournalCount) % AEGIS_FILE_MINIFILTER_QUEUE_CAPACITY;
        gFileJournalCount += 1;
    }

    gFileJournal[slot] = *record;
    gFileJournal[slot].Sequence = gFileNextSequence++;
    ExReleaseFastMutex(&gFileJournalLock);
}

static VOID AegisRecordFileEvent(
    _In_ PCWSTR operation,
    _Inout_ PFLT_CALLBACK_DATA data
) {
    AEGIS_FILE_EVENT_RECORD record;
    PFLT_FILE_NAME_INFORMATION file_name_info = NULL;

    RtlZeroMemory(&record, sizeof(record));
    KeQuerySystemTime(&record.Timestamp);
    record.ProcessId = HandleToULong(PsGetCurrentProcessId());

    if (operation != NULL) {
        RtlStringCchCopyW(record.Operation, RTL_NUMBER_OF(record.Operation), operation);
    }

    if (NT_SUCCESS(FltGetFileNameInformation(
            data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &file_name_info))) {
        FltParseFileNameInformation(file_name_info);
        AegisCopyUnicodeString(record.Path, RTL_NUMBER_OF(record.Path), &file_name_info->Name);
        FltReleaseFileNameInformation(file_name_info);
    } else if (data->Iopb->TargetFileObject != NULL) {
        AegisCopyUnicodeString(
            record.Path,
            RTL_NUMBER_OF(record.Path),
            &data->Iopb->TargetFileObject->FileName
        );
    }

    AegisFileJournalPush(&record);
}

static VOID AegisClearProtectedPaths(VOID) {
    ExAcquireFastMutex(&gProtectedPathLock);
    RtlZeroMemory(gProtectedPaths, sizeof(gProtectedPaths));
    gProtectedPathCount = 0;
    ExReleaseFastMutex(&gProtectedPathLock);
}

static NTSTATUS AegisAddProtectedPath(_In_ PCWSTR path) {
    UNICODE_STRING candidate;
    SIZE_T path_length = 0;
    ULONG index;
    NTSTATUS status = STATUS_SUCCESS;

    if (path == NULL || path[0] == UNICODE_NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = RtlStringCchLengthW(path, AEGIS_FILE_MAX_PATH_CHARS, &path_length);
    if (!NT_SUCCESS(status) || path_length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&candidate, path);
    ExAcquireFastMutex(&gProtectedPathLock);
    for (index = 0; index < gProtectedPathCount; index++) {
        UNICODE_STRING existing;
        RtlInitUnicodeString(&existing, gProtectedPaths[index]);
        if (RtlEqualUnicodeString(&existing, &candidate, TRUE)) {
            ExReleaseFastMutex(&gProtectedPathLock);
            return STATUS_SUCCESS;
        }
    }

    if (gProtectedPathCount >= AEGIS_FILE_PROTECTED_PATH_CAPACITY) {
        status = STATUS_INSUFFICIENT_RESOURCES;
    } else {
        RtlZeroMemory(
            gProtectedPaths[gProtectedPathCount],
            sizeof(gProtectedPaths[gProtectedPathCount])
        );
        status = RtlStringCchCopyW(
            gProtectedPaths[gProtectedPathCount],
            RTL_NUMBER_OF(gProtectedPaths[gProtectedPathCount]),
            path
        );
        if (NT_SUCCESS(status)) {
            gProtectedPathCount += 1;
        }
    }
    ExReleaseFastMutex(&gProtectedPathLock);
    return status;
}

static BOOLEAN AegisPathMatchesProtectedPrefix(_In_ PCUNICODE_STRING path) {
    ULONG index;
    BOOLEAN matched = FALSE;

    if (path == NULL || path->Buffer == NULL || path->Length == 0) {
        return FALSE;
    }

    ExAcquireFastMutex(&gProtectedPathLock);
    for (index = 0; index < gProtectedPathCount; index++) {
        UNICODE_STRING protected_path;
        SIZE_T protected_chars;

        RtlInitUnicodeString(&protected_path, gProtectedPaths[index]);
        if (protected_path.Length == 0) {
            continue;
        }
        if (!RtlPrefixUnicodeString(&protected_path, path, TRUE)) {
            continue;
        }

        protected_chars = protected_path.Length / sizeof(WCHAR);
        if (path->Length == protected_path.Length ||
            protected_path.Buffer[protected_chars - 1] == L'\\' ||
            path->Buffer[protected_chars] == L'\\') {
            matched = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&gProtectedPathLock);

    return matched;
}

static BOOLEAN AegisCreateHasWriteIntent(_In_ PFLT_CALLBACK_DATA Data) {
    ACCESS_MASK desired_access = 0;
    ULONG create_disposition;
    ULONG create_options;

    if (Data->Iopb->Parameters.Create.SecurityContext != NULL) {
        desired_access = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    }

    if ((desired_access &
         (FILE_WRITE_DATA |
          FILE_APPEND_DATA |
          FILE_WRITE_ATTRIBUTES |
          FILE_WRITE_EA |
          DELETE |
          WRITE_DAC |
          WRITE_OWNER)) != 0) {
        return TRUE;
    }

    create_disposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000ff;
    create_options = Data->Iopb->Parameters.Create.Options & 0x00ffffff;
    if ((create_options & FILE_DELETE_ON_CLOSE) != 0) {
        return TRUE;
    }

    switch (create_disposition) {
        case FILE_SUPERSEDE:
        case FILE_CREATE:
        case FILE_OPEN_IF:
        case FILE_OVERWRITE:
        case FILE_OVERWRITE_IF:
            return TRUE;
        default:
            return FALSE;
    }
}

static BOOLEAN AegisIsProtectedFileOperation(_In_ PFLT_CALLBACK_DATA Data) {
    PFLT_FILE_NAME_INFORMATION file_name_info = NULL;
    UNICODE_STRING resolved_path = {0};
    WCHAR resolved_buffer[AEGIS_FILE_MAX_PATH_CHARS];
    BOOLEAN is_protected = FALSE;

    RtlZeroMemory(resolved_buffer, sizeof(resolved_buffer));
    if (NT_SUCCESS(FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &file_name_info))) {
        FltParseFileNameInformation(file_name_info);
        AegisCopyUnicodeString(
            resolved_buffer,
            RTL_NUMBER_OF(resolved_buffer),
            &file_name_info->Name
        );
        FltReleaseFileNameInformation(file_name_info);
    } else if (Data->Iopb->TargetFileObject != NULL) {
        AegisCopyUnicodeString(
            resolved_buffer,
            RTL_NUMBER_OF(resolved_buffer),
            &Data->Iopb->TargetFileObject->FileName
        );
    }

    if (resolved_buffer[0] == UNICODE_NULL) {
        return FALSE;
    }

    RtlInitUnicodeString(&resolved_path, resolved_buffer);
    is_protected = AegisPathMatchesProtectedPrefix(&resolved_path);
    return is_protected;
}

static FLT_PREOP_CALLBACK_STATUS AegisDenyFileOperation(
    _In_ PCWSTR operation,
    _Inout_ PFLT_CALLBACK_DATA Data
) {
    AegisRecordFileEvent(operation, Data);
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

NTSTATUS
AegisFilePortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie
) {
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    gClientPort = ClientPort;
    *ConnectionPortCookie = NULL;
    return STATUS_SUCCESS;
}

VOID
AegisFilePortDisconnect(
    _In_opt_ PVOID ConnectionCookie
) {
    UNREFERENCED_PARAMETER(ConnectionCookie);

    if (gClientPort != NULL) {
        FltCloseClientPort(gFilterHandle, &gClientPort);
        gClientPort = NULL;
    }
}

NTSTATUS
AegisFilePortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
) {
    PAEGIS_FILE_QUERY_REQUEST request = (PAEGIS_FILE_QUERY_REQUEST)InputBuffer;
    ULONG protocol_version;
    ULONG command;

    UNREFERENCED_PARAMETER(PortCookie);

    *ReturnOutputBufferLength = 0;
    if (InputBuffer == NULL || OutputBuffer == NULL) {
        return STATUS_INVALID_USER_BUFFER;
    }
    if (InputBufferLength < (sizeof(ULONG) * 2)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    protocol_version = ((PULONG)InputBuffer)[0];
    command = ((PULONG)InputBuffer)[1];
    if (protocol_version != AEGIS_FILE_MINIFILTER_PROTOCOL_VERSION) {
        return STATUS_REVISION_MISMATCH;
    }

    if (command == AEGIS_FILE_COMMAND_QUERY_STATUS ||
        command == AEGIS_FILE_COMMAND_QUERY_EVENTS) {
        PAEGIS_FILE_QUERY_RESPONSE response = (PAEGIS_FILE_QUERY_RESPONSE)OutputBuffer;
        ULONG max_from_buffer;
        ULONG requested_max;
        ULONG response_index = 0;
        ULONG journal_index;
        ULONG available_bytes;

        if (InputBufferLength < sizeof(*request) || OutputBufferLength < sizeof(*response)) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        RtlZeroMemory(response, sizeof(*response));
        response->ProtocolVersion = AEGIS_FILE_MINIFILTER_PROTOCOL_VERSION;
        response->QueueCapacity = AEGIS_FILE_MINIFILTER_QUEUE_CAPACITY;

        ExAcquireFastMutex(&gFileJournalLock);
        response->OldestSequence = AegisFileJournalOldestSequenceUnlocked();
        response->CurrentSequence = AegisFileJournalCurrentSequenceUnlocked();
        if (request->LastSequence != 0 &&
            response->OldestSequence != 0 &&
            request->LastSequence + 1 < response->OldestSequence) {
            response->Overflowed = 1;
        }
        ExAcquireFastMutex(&gProtectedPathLock);
        response->ProtectedPathCount = AegisProtectedPathCountUnlocked();
        ExReleaseFastMutex(&gProtectedPathLock);

        if (command == AEGIS_FILE_COMMAND_QUERY_EVENTS) {
            available_bytes = OutputBufferLength - sizeof(*response);
            max_from_buffer = available_bytes / sizeof(AEGIS_FILE_EVENT_RECORD);
            requested_max = request->MaxEntries;
            if (requested_max == 0 || requested_max > max_from_buffer) {
                requested_max = max_from_buffer;
            }

            for (journal_index = 0; journal_index < gFileJournalCount; journal_index++) {
                ULONG slot =
                    (gFileJournalHead + journal_index) % AEGIS_FILE_MINIFILTER_QUEUE_CAPACITY;
                if (gFileJournal[slot].Sequence <= request->LastSequence) {
                    continue;
                }
                if (response_index >= requested_max) {
                    break;
                }

                ((PAEGIS_FILE_EVENT_RECORD)(response + 1))[response_index] = gFileJournal[slot];
                response_index += 1;
            }
        }

        response->ReturnedCount = response_index;
        ExReleaseFastMutex(&gFileJournalLock);

        *ReturnOutputBufferLength =
            sizeof(*response) + (response_index * sizeof(AEGIS_FILE_EVENT_RECORD));
        return STATUS_SUCCESS;
    }

    if (command == AEGIS_FILE_COMMAND_PROTECT_PATH ||
        command == AEGIS_FILE_COMMAND_CLEAR_PROTECTED_PATHS) {
        PAEGIS_FILE_PROTECTION_REQUEST protection_request =
            (PAEGIS_FILE_PROTECTION_REQUEST)InputBuffer;
        PAEGIS_FILE_PROTECTION_RESPONSE protection_response =
            (PAEGIS_FILE_PROTECTION_RESPONSE)OutputBuffer;
        NTSTATUS status = STATUS_SUCCESS;

        if (InputBufferLength < sizeof(*protection_request) ||
            OutputBufferLength < sizeof(*protection_response)) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (command == AEGIS_FILE_COMMAND_PROTECT_PATH) {
            status = AegisAddProtectedPath(protection_request->Path);
        } else {
            AegisClearProtectedPaths();
        }

        if (!NT_SUCCESS(status)) {
            return status;
        }

        RtlZeroMemory(protection_response, sizeof(*protection_response));
        protection_response->ProtocolVersion = AEGIS_FILE_MINIFILTER_PROTOCOL_VERSION;
        ExAcquireFastMutex(&gProtectedPathLock);
        protection_response->ProtectedPathCount = AegisProtectedPathCountUnlocked();
        ExReleaseFastMutex(&gProtectedPathLock);
        *ReturnOutputBufferLength = sizeof(*protection_response);
        return STATUS_SUCCESS;
    }

    return STATUS_INVALID_DEVICE_REQUEST;
}

FLT_PREOP_CALLBACK_STATUS
AegisFilePreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (AegisCreateHasWriteIntent(Data) && AegisIsProtectedFileOperation(Data)) {
        return AegisDenyFileOperation(L"block-create", Data);
    }

    AegisRecordFileEvent(L"open", Data);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
AegisFilePreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (AegisIsProtectedFileOperation(Data)) {
        return AegisDenyFileOperation(L"block-write", Data);
    }

    AegisRecordFileEvent(L"write", Data);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
AegisFilePreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
    FILE_INFORMATION_CLASS info_class;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    info_class = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (info_class == FileRenameInformation || info_class == FileRenameInformationEx) {
        if (AegisIsProtectedFileOperation(Data)) {
            return AegisDenyFileOperation(L"block-rename", Data);
        }
        AegisRecordFileEvent(L"rename", Data);
    } else if (info_class == FileDispositionInformation ||
               info_class == FileDispositionInformationEx) {
        if (AegisIsProtectedFileOperation(Data)) {
            return AegisDenyFileOperation(L"block-delete", Data);
        }
        AegisRecordFileEvent(L"delete", Data);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS
AegisFileUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
) {
    UNREFERENCED_PARAMETER(Flags);

    if (gServerPort != NULL) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
    }
    if (gClientPort != NULL) {
        FltCloseClientPort(gFilterHandle, &gClientPort);
        gClientPort = NULL;
    }
    if (gFilterHandle != NULL) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    NTSTATUS status;
    OBJECT_ATTRIBUTES object_attributes;
    PSECURITY_DESCRIPTOR security_descriptor = NULL;
    UNICODE_STRING port_name = RTL_CONSTANT_STRING(AEGIS_FILE_MINIFILTER_PORT_NAME_W);

    UNREFERENCED_PARAMETER(RegistryPath);

    ExInitializeFastMutex(&gFileJournalLock);
    ExInitializeFastMutex(&gProtectedPathLock);
    gFileJournalHead = 0;
    gFileJournalCount = 0;
    gFileNextSequence = 1;
    gProtectedPathCount = 0;
    RtlZeroMemory(gFileJournal, sizeof(gFileJournal));
    RtlZeroMemory(gProtectedPaths, sizeof(gProtectedPaths));

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    InitializeObjectAttributes(
        &object_attributes,
        &port_name,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );
    status = FltBuildDefaultSecurityDescriptor(&security_descriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }
    object_attributes.SecurityDescriptor = security_descriptor;

    status = FltCreateCommunicationPort(
        gFilterHandle,
        &gServerPort,
        &object_attributes,
        NULL,
        AegisFilePortConnect,
        AegisFilePortDisconnect,
        AegisFilePortMessage,
        1
    );
    FltFreeSecurityDescriptor(security_descriptor);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }

    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        if (gServerPort != NULL) {
            FltCloseCommunicationPort(gServerPort);
            gServerPort = NULL;
        }
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}
