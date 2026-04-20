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
    PAEGIS_FILE_QUERY_RESPONSE response = (PAEGIS_FILE_QUERY_RESPONSE)OutputBuffer;
    ULONG max_from_buffer;
    ULONG requested_max;
    ULONG response_index = 0;
    ULONG journal_index;
    ULONG available_bytes;

    UNREFERENCED_PARAMETER(PortCookie);

    *ReturnOutputBufferLength = 0;
    if (request == NULL || response == NULL) {
        return STATUS_INVALID_USER_BUFFER;
    }
    if (InputBufferLength < sizeof(*request) || OutputBufferLength < sizeof(*response)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request->ProtocolVersion != AEGIS_FILE_MINIFILTER_PROTOCOL_VERSION) {
        return STATUS_REVISION_MISMATCH;
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

    if (request->Command == AEGIS_FILE_COMMAND_QUERY_EVENTS) {
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

FLT_PREOP_CALLBACK_STATUS
AegisFilePreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

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
        AegisRecordFileEvent(L"rename", Data);
    } else if (info_class == FileDispositionInformation ||
               info_class == FileDispositionInformationEx) {
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
    gFileJournalHead = 0;
    gFileJournalCount = 0;
    gFileNextSequence = 1;
    RtlZeroMemory(gFileJournal, sizeof(gFileJournal));

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
