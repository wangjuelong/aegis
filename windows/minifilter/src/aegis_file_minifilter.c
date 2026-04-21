#include <fltKernel.h>
#include <bcrypt.h>
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
FAST_MUTEX gBlockEntryLock;
FAST_MUTEX gHashLookupGuardLock;

#define AEGIS_HASH_LOOKUP_GUARD_CAPACITY 64UL

typedef struct _AEGIS_ACTIVE_BLOCK_ENTRY {
    ULONG BlockKind;
    ULONG ProcessId;
    LARGE_INTEGER ExpiresAt;
    WCHAR Target[AEGIS_FILE_MAX_PATH_CHARS];
} AEGIS_ACTIVE_BLOCK_ENTRY, *PAEGIS_ACTIVE_BLOCK_ENTRY;

AEGIS_ACTIVE_BLOCK_ENTRY gBlockEntries[AEGIS_FILE_BLOCK_ENTRY_CAPACITY];
ULONG gBlockEntryCount = 0;
PETHREAD gHashLookupGuardThreads[AEGIS_HASH_LOOKUP_GUARD_CAPACITY];
ULONG gHashLookupGuardThreadCount = 0;

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
static VOID AegisCopyCanonicalPath(
    _Out_writes_(destination_count) PWCHAR destination,
    _In_ SIZE_T destination_count,
    _In_opt_ PCUNICODE_STRING source
);
static BOOLEAN AegisPathMatchesPrefix(_In_ PCUNICODE_STRING prefix, _In_ PCUNICODE_STRING path);
static BOOLEAN AegisPathMatchesProtectedPrefix(_In_ PCUNICODE_STRING path);
static VOID AegisPruneExpiredBlockEntriesLocked(VOID);
static VOID AegisCollectBlockCountsLocked(
    _Out_opt_ PULONG total_count,
    _Out_opt_ PULONG hash_count,
    _Out_opt_ PULONG pid_count,
    _Out_opt_ PULONG path_count
);
static VOID AegisClearBlockEntries(VOID);
static NTSTATUS AegisSetBlockEntry(_In_ const AEGIS_FILE_BLOCK_REQUEST* request);
static BOOLEAN AegisHasHashBlockEntries(VOID);
static BOOLEAN AegisEnterHashLookupGuard(VOID);
static VOID AegisExitHashLookupGuard(VOID);
static BOOLEAN AegisHashLookupGuardActive(VOID);
static BOOLEAN AegisRequestorPidBlocked(_In_ ULONG process_id);
static BOOLEAN AegisPathMatchesBlockPrefix(_In_ PCUNICODE_STRING path);
static NTSTATUS AegisComputeFileHandleSha256Hex(
    _In_ HANDLE file_handle,
    _Out_writes_(AEGIS_FILE_MAX_PATH_CHARS) PWCHAR hash_hex
);
static BOOLEAN AegisHashMatchesBlockEntryByHandle(
    _In_ HANDLE file_handle
);
static BOOLEAN AegisHashMatchesBlockEntryPreCreate(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING path
);
static BOOLEAN AegisResolveFilePath(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _Out_writes_(buffer_count) PWCHAR buffer,
    _In_ SIZE_T buffer_count
);
static BOOLEAN AegisResolveDestinationFilePath(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PFLT_CALLBACK_DATA Data,
    _Out_writes_(buffer_count) PWCHAR buffer,
    _In_ SIZE_T buffer_count
);
static BOOLEAN AegisCreateHasWriteIntent(_In_ PFLT_CALLBACK_DATA Data);
static BOOLEAN AegisIsProtectedFileOperation(_In_ PFLT_CALLBACK_DATA Data);
static FLT_PREOP_CALLBACK_STATUS AegisDenyFileOperation(
    _In_ PCWSTR operation,
    _Inout_ PFLT_CALLBACK_DATA Data
);
static FLT_PREOP_CALLBACK_STATUS AegisDenyFileOperationWithPath(
    _In_ PCWSTR operation,
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCUNICODE_STRING Path
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

    RtlZeroMemory(&record, sizeof(record));
    KeQuerySystemTime(&record.Timestamp);
    record.ProcessId = (ULONG)FltGetRequestorProcessId(data);

    if (operation != NULL) {
        RtlStringCchCopyW(record.Operation, RTL_NUMBER_OF(record.Operation), operation);
    }

    AegisResolveFilePath(data, record.Path, RTL_NUMBER_OF(record.Path));

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

static VOID AegisCopyCanonicalPath(
    _Out_writes_(destination_count) PWCHAR destination,
    _In_ SIZE_T destination_count,
    _In_opt_ PCUNICODE_STRING source
) {
    PCWSTR start;
    SIZE_T chars;
    SIZE_T index;
    ULONG slash_count = 0;

    if (destination == NULL || destination_count == 0) {
        return;
    }

    RtlZeroMemory(destination, destination_count * sizeof(WCHAR));
    if (source == NULL || source->Buffer == NULL || source->Length == 0) {
        return;
    }

    start = source->Buffer;
    chars = source->Length / sizeof(WCHAR);
    if (chars >= 4 &&
        start[0] == L'\\' &&
        start[1] == L'?' &&
        start[2] == L'?' &&
        start[3] == L'\\') {
        start += 4;
        chars -= 4;
    }

    if (chars >= 3 &&
        ((start[0] >= L'A' && start[0] <= L'Z') || (start[0] >= L'a' && start[0] <= L'z')) &&
        start[1] == L':' &&
        start[2] == L'\\') {
        start += 2;
        chars -= 2;
    } else if (chars >= 8 &&
               start[0] == L'\\' &&
               (start[1] == L'D' || start[1] == L'd')) {
        for (index = 0; index < chars; index++) {
            if (start[index] == L'\\') {
                slash_count += 1;
                if (slash_count == 3) {
                    start += index;
                    chars -= index;
                    break;
                }
            }
        }
    }

    if (chars >= destination_count) {
        chars = destination_count - 1;
    }
    if (chars > 0) {
        RtlCopyMemory(destination, start, chars * sizeof(WCHAR));
        destination[chars] = UNICODE_NULL;
    }
}

static BOOLEAN AegisPathMatchesPrefix(
    _In_ PCUNICODE_STRING prefix,
    _In_ PCUNICODE_STRING path
) {
    SIZE_T prefix_chars;
    WCHAR canonical_prefix_buffer[AEGIS_FILE_MAX_PATH_CHARS];
    WCHAR canonical_path_buffer[AEGIS_FILE_MAX_PATH_CHARS];
    UNICODE_STRING canonical_prefix;
    UNICODE_STRING canonical_path;

    if (prefix == NULL || prefix->Buffer == NULL || prefix->Length == 0 ||
        path == NULL || path->Buffer == NULL || path->Length == 0) {
        return FALSE;
    }

    if (!RtlPrefixUnicodeString(prefix, path, TRUE)) {
        AegisCopyCanonicalPath(
            canonical_prefix_buffer,
            RTL_NUMBER_OF(canonical_prefix_buffer),
            prefix
        );
        AegisCopyCanonicalPath(
            canonical_path_buffer,
            RTL_NUMBER_OF(canonical_path_buffer),
            path
        );
        RtlInitUnicodeString(&canonical_prefix, canonical_prefix_buffer);
        RtlInitUnicodeString(&canonical_path, canonical_path_buffer);
        if (canonical_prefix.Length == 0 ||
            canonical_path.Length == 0 ||
            !RtlPrefixUnicodeString(&canonical_prefix, &canonical_path, TRUE)) {
            return FALSE;
        }

        prefix = &canonical_prefix;
        path = &canonical_path;
    }

    prefix_chars = prefix->Length / sizeof(WCHAR);
    if (path->Length == prefix->Length ||
        prefix->Buffer[prefix_chars - 1] == L'\\' ||
        path->Buffer[prefix_chars] == L'\\') {
        return TRUE;
    }

    return FALSE;
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

        RtlInitUnicodeString(&protected_path, gProtectedPaths[index]);
        if (AegisPathMatchesPrefix(&protected_path, path)) {
            matched = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&gProtectedPathLock);

    return matched;
}

static VOID AegisPruneExpiredBlockEntriesLocked(VOID) {
    LARGE_INTEGER now;
    ULONG read_index;
    ULONG write_index = 0;

    KeQuerySystemTime(&now);
    for (read_index = 0; read_index < gBlockEntryCount; read_index++) {
        if (gBlockEntries[read_index].ExpiresAt.QuadPart <= now.QuadPart) {
            continue;
        }

        if (write_index != read_index) {
            gBlockEntries[write_index] = gBlockEntries[read_index];
        }
        write_index += 1;
    }

    if (write_index < gBlockEntryCount) {
        RtlZeroMemory(
            &gBlockEntries[write_index],
            sizeof(AEGIS_ACTIVE_BLOCK_ENTRY) * (gBlockEntryCount - write_index)
        );
    }
    gBlockEntryCount = write_index;
}

static VOID AegisCollectBlockCountsLocked(
    _Out_opt_ PULONG total_count,
    _Out_opt_ PULONG hash_count,
    _Out_opt_ PULONG pid_count,
    _Out_opt_ PULONG path_count
) {
    ULONG index;
    ULONG hash_total = 0;
    ULONG pid_total = 0;
    ULONG path_total = 0;

    if (total_count != NULL) {
        *total_count = gBlockEntryCount;
    }

    for (index = 0; index < gBlockEntryCount; index++) {
        switch (gBlockEntries[index].BlockKind) {
            case AEGIS_FILE_BLOCK_KIND_HASH:
                hash_total += 1;
                break;
            case AEGIS_FILE_BLOCK_KIND_PID:
                pid_total += 1;
                break;
            case AEGIS_FILE_BLOCK_KIND_PATH:
                path_total += 1;
                break;
            default:
                break;
        }
    }

    if (hash_count != NULL) {
        *hash_count = hash_total;
    }
    if (pid_count != NULL) {
        *pid_count = pid_total;
    }
    if (path_count != NULL) {
        *path_count = path_total;
    }
}

static VOID AegisClearBlockEntries(VOID) {
    ExAcquireFastMutex(&gBlockEntryLock);
    RtlZeroMemory(gBlockEntries, sizeof(gBlockEntries));
    gBlockEntryCount = 0;
    ExReleaseFastMutex(&gBlockEntryLock);
}

static NTSTATUS AegisSetBlockEntry(_In_ const AEGIS_FILE_BLOCK_REQUEST* request) {
    LARGE_INTEGER now;
    LARGE_INTEGER expires_at;
    UNICODE_STRING target;
    ULONG index;
    NTSTATUS status = STATUS_SUCCESS;

    if (request == NULL || request->TtlSeconds == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->BlockKind != AEGIS_FILE_BLOCK_KIND_HASH &&
        request->BlockKind != AEGIS_FILE_BLOCK_KIND_PID &&
        request->BlockKind != AEGIS_FILE_BLOCK_KIND_PATH) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->BlockKind == AEGIS_FILE_BLOCK_KIND_PID && request->ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->BlockKind != AEGIS_FILE_BLOCK_KIND_PID &&
        request->Target[0] == UNICODE_NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&target, request->Target);
    KeQuerySystemTime(&now);
    expires_at.QuadPart =
        now.QuadPart + ((LONGLONG)request->TtlSeconds * 10 * 1000 * 1000);

    ExAcquireFastMutex(&gBlockEntryLock);
    AegisPruneExpiredBlockEntriesLocked();

    for (index = 0; index < gBlockEntryCount; index++) {
        BOOLEAN same_target = FALSE;
        UNICODE_STRING existing_target;

        if (gBlockEntries[index].BlockKind != request->BlockKind) {
            continue;
        }
        if (request->BlockKind == AEGIS_FILE_BLOCK_KIND_PID) {
            same_target = gBlockEntries[index].ProcessId == request->ProcessId;
        } else {
            RtlInitUnicodeString(&existing_target, gBlockEntries[index].Target);
            same_target = RtlEqualUnicodeString(&existing_target, &target, TRUE);
        }

        if (!same_target) {
            continue;
        }

        gBlockEntries[index].ProcessId = request->ProcessId;
        gBlockEntries[index].ExpiresAt = expires_at;
        if (request->BlockKind != AEGIS_FILE_BLOCK_KIND_PID) {
            RtlZeroMemory(gBlockEntries[index].Target, sizeof(gBlockEntries[index].Target));
            status = RtlStringCchCopyW(
                gBlockEntries[index].Target,
                RTL_NUMBER_OF(gBlockEntries[index].Target),
                request->Target
            );
        }
        ExReleaseFastMutex(&gBlockEntryLock);
        return status;
    }

    if (gBlockEntryCount >= AEGIS_FILE_BLOCK_ENTRY_CAPACITY) {
        ExReleaseFastMutex(&gBlockEntryLock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(&gBlockEntries[gBlockEntryCount], sizeof(gBlockEntries[gBlockEntryCount]));
    gBlockEntries[gBlockEntryCount].BlockKind = request->BlockKind;
    gBlockEntries[gBlockEntryCount].ProcessId = request->ProcessId;
    gBlockEntries[gBlockEntryCount].ExpiresAt = expires_at;
    if (request->BlockKind != AEGIS_FILE_BLOCK_KIND_PID) {
        status = RtlStringCchCopyW(
            gBlockEntries[gBlockEntryCount].Target,
            RTL_NUMBER_OF(gBlockEntries[gBlockEntryCount].Target),
            request->Target
        );
        if (!NT_SUCCESS(status)) {
            ExReleaseFastMutex(&gBlockEntryLock);
            return status;
        }
    }
    gBlockEntryCount += 1;
    ExReleaseFastMutex(&gBlockEntryLock);
    return STATUS_SUCCESS;
}

static BOOLEAN AegisHasHashBlockEntries(VOID) {
    BOOLEAN found = FALSE;
    ULONG index;

    ExAcquireFastMutex(&gBlockEntryLock);
    AegisPruneExpiredBlockEntriesLocked();
    for (index = 0; index < gBlockEntryCount; index++) {
        if (gBlockEntries[index].BlockKind == AEGIS_FILE_BLOCK_KIND_HASH) {
            found = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&gBlockEntryLock);
    return found;
}

static BOOLEAN AegisEnterHashLookupGuard(VOID) {
    PETHREAD current_thread = PsGetCurrentThread();
    ULONG index;

    ExAcquireFastMutex(&gHashLookupGuardLock);
    for (index = 0; index < gHashLookupGuardThreadCount; index++) {
        if (gHashLookupGuardThreads[index] == current_thread) {
            ExReleaseFastMutex(&gHashLookupGuardLock);
            return TRUE;
        }
    }
    if (gHashLookupGuardThreadCount >= AEGIS_HASH_LOOKUP_GUARD_CAPACITY) {
        ExReleaseFastMutex(&gHashLookupGuardLock);
        return FALSE;
    }
    gHashLookupGuardThreads[gHashLookupGuardThreadCount++] = current_thread;
    ExReleaseFastMutex(&gHashLookupGuardLock);
    return TRUE;
}

static VOID AegisExitHashLookupGuard(VOID) {
    PETHREAD current_thread = PsGetCurrentThread();
    ULONG index;

    ExAcquireFastMutex(&gHashLookupGuardLock);
    for (index = 0; index < gHashLookupGuardThreadCount; index++) {
        if (gHashLookupGuardThreads[index] == current_thread) {
            ULONG tail_index = gHashLookupGuardThreadCount - 1;
            if (index != tail_index) {
                gHashLookupGuardThreads[index] = gHashLookupGuardThreads[tail_index];
            }
            gHashLookupGuardThreads[tail_index] = NULL;
            gHashLookupGuardThreadCount -= 1;
            break;
        }
    }
    ExReleaseFastMutex(&gHashLookupGuardLock);
}

static BOOLEAN AegisHashLookupGuardActive(VOID) {
    PETHREAD current_thread = PsGetCurrentThread();
    ULONG index;
    BOOLEAN active = FALSE;

    ExAcquireFastMutex(&gHashLookupGuardLock);
    for (index = 0; index < gHashLookupGuardThreadCount; index++) {
        if (gHashLookupGuardThreads[index] == current_thread) {
            active = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&gHashLookupGuardLock);
    return active;
}

static BOOLEAN AegisRequestorPidBlocked(_In_ ULONG process_id) {
    BOOLEAN blocked = FALSE;
    ULONG index;

    if (process_id == 0) {
        return FALSE;
    }

    ExAcquireFastMutex(&gBlockEntryLock);
    AegisPruneExpiredBlockEntriesLocked();
    for (index = 0; index < gBlockEntryCount; index++) {
        if (gBlockEntries[index].BlockKind == AEGIS_FILE_BLOCK_KIND_PID &&
            gBlockEntries[index].ProcessId == process_id) {
            blocked = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&gBlockEntryLock);
    return blocked;
}

static BOOLEAN AegisPathMatchesBlockPrefix(_In_ PCUNICODE_STRING path) {
    BOOLEAN blocked = FALSE;
    ULONG index;

    if (path == NULL || path->Buffer == NULL || path->Length == 0) {
        return FALSE;
    }

    ExAcquireFastMutex(&gBlockEntryLock);
    AegisPruneExpiredBlockEntriesLocked();
    for (index = 0; index < gBlockEntryCount; index++) {
        UNICODE_STRING target;

        if (gBlockEntries[index].BlockKind != AEGIS_FILE_BLOCK_KIND_PATH) {
            continue;
        }
        RtlInitUnicodeString(&target, gBlockEntries[index].Target);
        if (AegisPathMatchesPrefix(&target, path)) {
            blocked = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&gBlockEntryLock);
    return blocked;
}

static BOOLEAN AegisResolveFilePath(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _Out_writes_(buffer_count) PWCHAR buffer,
    _In_ SIZE_T buffer_count
) {
    PFLT_FILE_NAME_INFORMATION file_name_info = NULL;

    if (buffer == NULL || buffer_count == 0) {
        return FALSE;
    }

    RtlZeroMemory(buffer, buffer_count * sizeof(WCHAR));
    if (NT_SUCCESS(FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &file_name_info))) {
        FltParseFileNameInformation(file_name_info);
        AegisCopyUnicodeString(buffer, buffer_count, &file_name_info->Name);
        FltReleaseFileNameInformation(file_name_info);
    } else if (Data->Iopb->TargetFileObject != NULL) {
        AegisCopyUnicodeString(
            buffer,
            buffer_count,
            &Data->Iopb->TargetFileObject->FileName
        );
    }

    return buffer[0] != UNICODE_NULL;
}

static BOOLEAN AegisResolveDestinationFilePath(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PFLT_CALLBACK_DATA Data,
    _Out_writes_(buffer_count) PWCHAR buffer,
    _In_ SIZE_T buffer_count
) {
    PFLT_FILE_NAME_INFORMATION file_name_info = NULL;
    HANDLE root_directory = NULL;
    PWSTR file_name = NULL;
    ULONG file_name_length = 0;
    FILE_INFORMATION_CLASS info_class;
    NTSTATUS status;
    PFILE_OBJECT parent_of_target = NULL;

    if (FltObjects == NULL ||
        FltObjects->Instance == NULL ||
        Data == NULL ||
        buffer == NULL ||
        buffer_count == 0) {
        return FALSE;
    }

    RtlZeroMemory(buffer, buffer_count * sizeof(WCHAR));
    info_class = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    parent_of_target = Data->Iopb->Parameters.SetFileInformation.ParentOfTarget;
    switch (info_class) {
        case FileRenameInformation:
        case FileRenameInformationBypassAccessCheck:
        case FileRenameInformationEx: {
#ifdef FileRenameInformationExBypassAccessCheck
        case FileRenameInformationExBypassAccessCheck:
#endif
            PFILE_RENAME_INFORMATION rename_info =
                (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
            if (rename_info == NULL) {
                return FALSE;
            }
            root_directory = rename_info->RootDirectory;
            file_name = rename_info->FileName;
            file_name_length = rename_info->FileNameLength;
            break;
        }
        case FileLinkInformation:
        case FileLinkInformationBypassAccessCheck:
        case FileLinkInformationEx: {
#ifdef FileLinkInformationExBypassAccessCheck
        case FileLinkInformationExBypassAccessCheck:
#endif
            PFILE_LINK_INFORMATION link_info =
                (PFILE_LINK_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
            if (link_info == NULL) {
                return FALSE;
            }
            root_directory = link_info->RootDirectory;
            file_name = link_info->FileName;
            file_name_length = link_info->FileNameLength;
            break;
        }
        default:
            return FALSE;
    }

    if (file_name == NULL || file_name_length == 0) {
        return FALSE;
    }

    if (parent_of_target != NULL && parent_of_target->FileName.Buffer != NULL) {
        SIZE_T parent_chars;
        SIZE_T child_chars;
        SIZE_T offset;

        AegisCopyUnicodeString(buffer, buffer_count, &parent_of_target->FileName);
        parent_chars = wcslen(buffer);
        offset = parent_chars;
        if (offset > 0 && buffer[offset - 1] != L'\\') {
            if (offset + 1 >= buffer_count) {
                return FALSE;
            }
            buffer[offset++] = L'\\';
            buffer[offset] = UNICODE_NULL;
        }

        child_chars = file_name_length / sizeof(WCHAR);
        if (child_chars > 0 && file_name[0] == L'\\') {
            file_name += 1;
            child_chars -= 1;
        }
        if (offset + child_chars >= buffer_count) {
            child_chars = buffer_count - offset - 1;
        }
        if (child_chars > 0) {
            RtlCopyMemory(buffer + offset, file_name, child_chars * sizeof(WCHAR));
            buffer[offset + child_chars] = UNICODE_NULL;
            return TRUE;
        }
    }

    if ((file_name_length / sizeof(WCHAR)) < buffer_count) {
        RtlCopyMemory(buffer, file_name, file_name_length);
        buffer[file_name_length / sizeof(WCHAR)] = UNICODE_NULL;
    }

    status = FltGetDestinationFileNameInformation(
        FltObjects->Instance,
        FltObjects->FileObject,
        parent_of_target != NULL ? parent_of_target : root_directory,
        file_name,
        file_name_length,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY,
        &file_name_info
    );
    if (!NT_SUCCESS(status) || file_name_info == NULL) {
        return buffer[0] != UNICODE_NULL;
    }

    FltParseFileNameInformation(file_name_info);
    AegisCopyUnicodeString(buffer, buffer_count, &file_name_info->Name);
    FltReleaseFileNameInformation(file_name_info);
    return buffer[0] != UNICODE_NULL;
}

static NTSTATUS AegisComputeFileHandleSha256Hex(
    _In_ HANDLE file_handle,
    _Out_writes_(AEGIS_FILE_MAX_PATH_CHARS) PWCHAR hash_hex
) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash_handle = NULL;
    FILE_STANDARD_INFORMATION standard_info;
    ULONG object_length = 0;
    ULONG hash_length = 0;
    ULONG result_length = 0;
    PUCHAR hash_object = NULL;
    PUCHAR hash_bytes = NULL;
    PUCHAR io_buffer = NULL;
    LARGE_INTEGER offset;
    NTSTATUS status;
    ULONG bytes_to_read;
    ULONG bytes_read;
    static const WCHAR kHex[] = L"0123456789abcdef";
    ULONG index;
    IO_STATUS_BLOCK io_status;

    if (file_handle == NULL || hash_hex == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(hash_hex, AEGIS_FILE_MAX_PATH_CHARS * sizeof(WCHAR));
    RtlZeroMemory(&standard_info, sizeof(standard_info));
    status = ZwQueryInformationFile(
        file_handle,
        &io_status,
        &standard_info,
        sizeof(standard_info),
        FileStandardInformation
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (standard_info.EndOfFile.QuadPart < 0) {
        return STATUS_FILE_INVALID;
    }

    status = BCryptOpenAlgorithmProvider(
        &algorithm,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_PROV_DISPATCH
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = BCryptGetProperty(
        algorithm,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&object_length,
        sizeof(object_length),
        &result_length,
        0
    );
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    status = BCryptGetProperty(
        algorithm,
        BCRYPT_HASH_LENGTH,
        (PUCHAR)&hash_length,
        sizeof(hash_length),
        &result_length,
        0
    );
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    if ((hash_length * 2) + 1 > AEGIS_FILE_MAX_PATH_CHARS) {
        status = STATUS_BUFFER_TOO_SMALL;
        goto Cleanup;
    }

    hash_object = ExAllocatePoolZero(NonPagedPoolNx, object_length, 'hgbA');
    hash_bytes = ExAllocatePoolZero(NonPagedPoolNx, hash_length, 'bgbA');
    io_buffer = ExAllocatePoolZero(NonPagedPoolNx, 64 * 1024, 'rgbA');
    if (hash_object == NULL || hash_bytes == NULL || io_buffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    status = BCryptCreateHash(
        algorithm,
        &hash_handle,
        hash_object,
        object_length,
        NULL,
        0,
        0
    );
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    offset.QuadPart = 0;
    while (offset.QuadPart < standard_info.EndOfFile.QuadPart) {
        bytes_to_read = 64 * 1024;
        if ((standard_info.EndOfFile.QuadPart - offset.QuadPart) < bytes_to_read) {
            bytes_to_read = (ULONG)(standard_info.EndOfFile.QuadPart - offset.QuadPart);
        }
        if (bytes_to_read == 0) {
            break;
        }

        bytes_read = 0;
        status = ZwReadFile(
            file_handle,
            NULL,
            NULL,
            NULL,
            &io_status,
            io_buffer,
            bytes_to_read,
            &offset,
            NULL
        );
        bytes_read = (ULONG)io_status.Information;
        if (!NT_SUCCESS(status) || bytes_read == 0) {
            break;
        }

        status = BCryptHashData(hash_handle, io_buffer, bytes_read, 0);
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }
        offset.QuadPart += bytes_read;
    }

    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    status = BCryptFinishHash(hash_handle, hash_bytes, hash_length, 0);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    for (index = 0; index < hash_length; index++) {
        hash_hex[index * 2] = kHex[(hash_bytes[index] >> 4) & 0x0f];
        hash_hex[(index * 2) + 1] = kHex[hash_bytes[index] & 0x0f];
    }
    hash_hex[hash_length * 2] = UNICODE_NULL;
    status = STATUS_SUCCESS;

Cleanup:
    if (hash_handle != NULL) {
        BCryptDestroyHash(hash_handle);
    }
    if (algorithm != NULL) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    if (io_buffer != NULL) {
        ExFreePoolWithTag(io_buffer, 'rgbA');
    }
    if (hash_bytes != NULL) {
        ExFreePoolWithTag(hash_bytes, 'bgbA');
    }
    if (hash_object != NULL) {
        ExFreePoolWithTag(hash_object, 'hgbA');
    }
    return status;
}

static BOOLEAN AegisHashMatchesBlockEntryByHandle(_In_ HANDLE file_handle) {
    BOOLEAN blocked = FALSE;
    WCHAR hash_hex[AEGIS_FILE_MAX_PATH_CHARS];
    UNICODE_STRING candidate_hash;
    ULONG index;

    if (!NT_SUCCESS(AegisComputeFileHandleSha256Hex(file_handle, hash_hex))) {
        return FALSE;
    }

    RtlInitUnicodeString(&candidate_hash, hash_hex);
    ExAcquireFastMutex(&gBlockEntryLock);
    AegisPruneExpiredBlockEntriesLocked();
    for (index = 0; index < gBlockEntryCount; index++) {
        UNICODE_STRING configured_hash;

        if (gBlockEntries[index].BlockKind != AEGIS_FILE_BLOCK_KIND_HASH) {
            continue;
        }
        RtlInitUnicodeString(&configured_hash, gBlockEntries[index].Target);
        if (RtlEqualUnicodeString(&configured_hash, &candidate_hash, TRUE)) {
            blocked = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&gBlockEntryLock);
    return blocked;
}

static BOOLEAN AegisHashMatchesBlockEntryPreCreate(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING path
) {
    HANDLE file_handle = NULL;
    OBJECT_ATTRIBUTES object_attributes;
    IO_STATUS_BLOCK io_status;
    NTSTATUS status;
    BOOLEAN blocked = FALSE;

    if (FltObjects == NULL ||
        FltObjects->Instance == NULL ||
        path == NULL ||
        path->Buffer == NULL ||
        path->Length == 0) {
        return FALSE;
    }
    if (!AegisEnterHashLookupGuard()) {
        return FALSE;
    }

    InitializeObjectAttributes(
        &object_attributes,
        (PUNICODE_STRING)path,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );
    status = FltCreateFile(
        gFilterHandle,
        FltObjects->Instance,
        &file_handle,
        FILE_GENERIC_READ | SYNCHRONIZE,
        &object_attributes,
        &io_status,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0,
        0
    );
    AegisExitHashLookupGuard();

    if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
        status == STATUS_OBJECT_PATH_NOT_FOUND ||
        status == STATUS_FILE_IS_A_DIRECTORY ||
        status == STATUS_NOT_A_DIRECTORY) {
        return FALSE;
    }
    if (!NT_SUCCESS(status)) {
        return TRUE;
    }

    blocked = AegisHashMatchesBlockEntryByHandle(file_handle);
    ZwClose(file_handle);
    return blocked;
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
    UNICODE_STRING resolved_path = {0};
    WCHAR resolved_buffer[AEGIS_FILE_MAX_PATH_CHARS];

    RtlZeroMemory(resolved_buffer, sizeof(resolved_buffer));
    if (!AegisResolveFilePath(Data, resolved_buffer, RTL_NUMBER_OF(resolved_buffer))) {
        return FALSE;
    }

    RtlInitUnicodeString(&resolved_path, resolved_buffer);
    return AegisPathMatchesProtectedPrefix(&resolved_path);
}

static FLT_PREOP_CALLBACK_STATUS AegisDenyFileOperation(
    _In_ PCWSTR operation,
    _Inout_ PFLT_CALLBACK_DATA Data
) {
    return AegisDenyFileOperationWithPath(operation, Data, NULL);
}

static FLT_PREOP_CALLBACK_STATUS AegisDenyFileOperationWithPath(
    _In_ PCWSTR operation,
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCUNICODE_STRING Path
) {
    AEGIS_FILE_EVENT_RECORD record;

    RtlZeroMemory(&record, sizeof(record));
    KeQuerySystemTime(&record.Timestamp);
    record.ProcessId = (ULONG)FltGetRequestorProcessId(Data);
    if (operation != NULL) {
        RtlStringCchCopyW(record.Operation, RTL_NUMBER_OF(record.Operation), operation);
    }
    if (Path != NULL) {
        AegisCopyUnicodeString(record.Path, RTL_NUMBER_OF(record.Path), Path);
    } else {
        AegisResolveFilePath(Data, record.Path, RTL_NUMBER_OF(record.Path));
    }
    AegisFileJournalPush(&record);
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
        command == AEGIS_FILE_COMMAND_QUERY_EVENTS ||
        command == AEGIS_FILE_COMMAND_QUERY_BLOCK_STATE) {
        PAEGIS_FILE_QUERY_RESPONSE response = (PAEGIS_FILE_QUERY_RESPONSE)OutputBuffer;
        ULONG max_from_buffer;
        ULONG requested_max;
        ULONG response_index = 0;
        ULONG journal_index;
        ULONG available_bytes;
        ULONG block_total = 0;
        ULONG hash_total = 0;
        ULONG pid_total = 0;
        ULONG path_total = 0;

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
        ExAcquireFastMutex(&gBlockEntryLock);
        AegisPruneExpiredBlockEntriesLocked();
        AegisCollectBlockCountsLocked(
            &block_total,
            &hash_total,
            &pid_total,
            &path_total
        );
        response->BlockEntryCount = block_total;
        response->HashBlockCount = hash_total;
        response->PidBlockCount = pid_total;
        response->PathBlockCount = path_total;
        ExReleaseFastMutex(&gBlockEntryLock);

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
        if (command == AEGIS_FILE_COMMAND_QUERY_BLOCK_STATE) {
            available_bytes = OutputBufferLength - sizeof(*response);
            max_from_buffer = available_bytes / sizeof(AEGIS_FILE_BLOCK_ENTRY_RECORD);
            requested_max = request->MaxEntries;
            if (requested_max == 0 || requested_max > max_from_buffer) {
                requested_max = max_from_buffer;
            }

            ExAcquireFastMutex(&gBlockEntryLock);
            AegisPruneExpiredBlockEntriesLocked();
            for (journal_index = 0; journal_index < gBlockEntryCount; journal_index++) {
                PAEGIS_FILE_BLOCK_ENTRY_RECORD record;
                LARGE_INTEGER now;
                LONGLONG remaining_100ns;

                if (response_index >= requested_max) {
                    break;
                }
                record =
                    &((PAEGIS_FILE_BLOCK_ENTRY_RECORD)(response + 1))[response_index];
                RtlZeroMemory(record, sizeof(*record));
                record->BlockKind = gBlockEntries[journal_index].BlockKind;
                record->ProcessId = gBlockEntries[journal_index].ProcessId;
                RtlStringCchCopyW(
                    record->Target,
                    RTL_NUMBER_OF(record->Target),
                    gBlockEntries[journal_index].Target
                );
                KeQuerySystemTime(&now);
                remaining_100ns =
                    gBlockEntries[journal_index].ExpiresAt.QuadPart - now.QuadPart;
                if (remaining_100ns > 0) {
                    record->TtlSecondsRemaining =
                        (ULONG)((remaining_100ns + ((10 * 1000 * 1000) - 1)) /
                                (10 * 1000 * 1000));
                }
                response_index += 1;
            }
            response->ReturnedCount = response_index;
            ExReleaseFastMutex(&gBlockEntryLock);
        }

        *ReturnOutputBufferLength =
            sizeof(*response) +
            (response_index *
             (command == AEGIS_FILE_COMMAND_QUERY_BLOCK_STATE
                  ? sizeof(AEGIS_FILE_BLOCK_ENTRY_RECORD)
                  : sizeof(AEGIS_FILE_EVENT_RECORD)));
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

    if (command == AEGIS_FILE_COMMAND_SET_BLOCK_ENTRY ||
        command == AEGIS_FILE_COMMAND_CLEAR_BLOCK_ENTRIES) {
        PAEGIS_FILE_BLOCK_REQUEST block_request =
            (PAEGIS_FILE_BLOCK_REQUEST)InputBuffer;
        PAEGIS_FILE_BLOCK_RESPONSE block_response =
            (PAEGIS_FILE_BLOCK_RESPONSE)OutputBuffer;
        NTSTATUS status = STATUS_SUCCESS;

        if (InputBufferLength < sizeof(*block_request) ||
            OutputBufferLength < sizeof(*block_response)) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (command == AEGIS_FILE_COMMAND_SET_BLOCK_ENTRY) {
            status = AegisSetBlockEntry(block_request);
        } else {
            AegisClearBlockEntries();
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        RtlZeroMemory(block_response, sizeof(*block_response));
        block_response->ProtocolVersion = AEGIS_FILE_MINIFILTER_PROTOCOL_VERSION;
        ExAcquireFastMutex(&gBlockEntryLock);
        AegisPruneExpiredBlockEntriesLocked();
        AegisCollectBlockCountsLocked(
            &block_response->BlockEntryCount,
            &block_response->HashBlockCount,
            &block_response->PidBlockCount,
            &block_response->PathBlockCount
        );
        ExReleaseFastMutex(&gBlockEntryLock);
        *ReturnOutputBufferLength = sizeof(*block_response);
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
    ULONG requestor_pid = (ULONG)FltGetRequestorProcessId(Data);
    WCHAR resolved_path_buffer[AEGIS_FILE_MAX_PATH_CHARS];
    UNICODE_STRING resolved_path;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    RtlZeroMemory(resolved_path_buffer, sizeof(resolved_path_buffer));
    if (AegisRequestorPidBlocked(requestor_pid)) {
        return AegisDenyFileOperation(L"block-pid", Data);
    }
    if (AegisResolveFilePath(Data, resolved_path_buffer, RTL_NUMBER_OF(resolved_path_buffer))) {
        RtlInitUnicodeString(&resolved_path, resolved_path_buffer);
        if (AegisPathMatchesBlockPrefix(&resolved_path)) {
            return AegisDenyFileOperation(L"block-path", Data);
        }
    }
    if (AegisCreateHasWriteIntent(Data) && AegisIsProtectedFileOperation(Data)) {
        return AegisDenyFileOperation(L"block-create", Data);
    }
    if (AegisHasHashBlockEntries() && !AegisHashLookupGuardActive()) {
        if (resolved_path_buffer[0] != UNICODE_NULL &&
            AegisHashMatchesBlockEntryPreCreate(FltObjects, &resolved_path)) {
            return AegisDenyFileOperation(L"block-hash", Data);
        }
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
    ULONG requestor_pid = (ULONG)FltGetRequestorProcessId(Data);
    WCHAR resolved_path_buffer[AEGIS_FILE_MAX_PATH_CHARS];
    UNICODE_STRING resolved_path;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    RtlZeroMemory(resolved_path_buffer, sizeof(resolved_path_buffer));
    if (AegisRequestorPidBlocked(requestor_pid)) {
        return AegisDenyFileOperation(L"block-pid", Data);
    }
    if (AegisResolveFilePath(Data, resolved_path_buffer, RTL_NUMBER_OF(resolved_path_buffer))) {
        RtlInitUnicodeString(&resolved_path, resolved_path_buffer);
        if (AegisPathMatchesBlockPrefix(&resolved_path)) {
            return AegisDenyFileOperation(L"block-path", Data);
        }
    }
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
    ULONG requestor_pid = (ULONG)FltGetRequestorProcessId(Data);
    WCHAR resolved_path_buffer[AEGIS_FILE_MAX_PATH_CHARS];
    WCHAR destination_path_buffer[AEGIS_FILE_MAX_PATH_CHARS];
    UNICODE_STRING resolved_path;
    UNICODE_STRING destination_path;
    BOOLEAN has_destination_path = FALSE;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    RtlZeroMemory(resolved_path_buffer, sizeof(resolved_path_buffer));
    RtlZeroMemory(destination_path_buffer, sizeof(destination_path_buffer));
    if (AegisRequestorPidBlocked(requestor_pid)) {
        return AegisDenyFileOperation(L"block-pid", Data);
    }
    if (AegisResolveFilePath(Data, resolved_path_buffer, RTL_NUMBER_OF(resolved_path_buffer))) {
        RtlInitUnicodeString(&resolved_path, resolved_path_buffer);
        if (AegisPathMatchesBlockPrefix(&resolved_path)) {
            return AegisDenyFileOperation(L"block-path", Data);
        }
    }

    info_class = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    has_destination_path = AegisResolveDestinationFilePath(
        FltObjects,
        Data,
        destination_path_buffer,
        RTL_NUMBER_OF(destination_path_buffer)
    );
    if (has_destination_path) {
        RtlInitUnicodeString(&destination_path, destination_path_buffer);
    }
    if (info_class == FileRenameInformation ||
        info_class == FileRenameInformationBypassAccessCheck ||
        info_class == FileRenameInformationEx ||
#ifdef FileRenameInformationExBypassAccessCheck
        info_class == FileRenameInformationExBypassAccessCheck ||
#endif
        info_class == FileLinkInformation ||
        info_class == FileLinkInformationBypassAccessCheck ||
        info_class == FileLinkInformationEx
#ifdef FileLinkInformationExBypassAccessCheck
        || info_class == FileLinkInformationExBypassAccessCheck
#endif
        ) {
        if (has_destination_path && AegisPathMatchesBlockPrefix(&destination_path)) {
            return AegisDenyFileOperationWithPath(
                L"block-pth-dst",
                Data,
                &destination_path
            );
        }
    }

    if (info_class == FileRenameInformation ||
        info_class == FileRenameInformationBypassAccessCheck ||
        info_class == FileRenameInformationEx
#ifdef FileRenameInformationExBypassAccessCheck
        || info_class == FileRenameInformationExBypassAccessCheck
#endif
        ) {
        if (AegisIsProtectedFileOperation(Data)) {
            return AegisDenyFileOperation(L"block-rename", Data);
        }
        if (has_destination_path && AegisPathMatchesProtectedPrefix(&destination_path)) {
            return AegisDenyFileOperationWithPath(
                L"block-ren-dst",
                Data,
                &destination_path
            );
        }
        AegisRecordFileEvent(L"rename", Data);
    } else if (info_class == FileLinkInformation ||
               info_class == FileLinkInformationBypassAccessCheck ||
               info_class == FileLinkInformationEx
#ifdef FileLinkInformationExBypassAccessCheck
               || info_class == FileLinkInformationExBypassAccessCheck
#endif
               ) {
        if (AegisIsProtectedFileOperation(Data)) {
            return AegisDenyFileOperation(L"block-link", Data);
        }
        if (has_destination_path && AegisPathMatchesProtectedPrefix(&destination_path)) {
            return AegisDenyFileOperationWithPath(
                L"block-lnk-dst",
                Data,
                &destination_path
            );
        }
        AegisRecordFileEvent(L"link", Data);
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

    AegisClearProtectedPaths();
    AegisClearBlockEntries();
    ExAcquireFastMutex(&gHashLookupGuardLock);
    RtlZeroMemory(gHashLookupGuardThreads, sizeof(gHashLookupGuardThreads));
    gHashLookupGuardThreadCount = 0;
    ExReleaseFastMutex(&gHashLookupGuardLock);

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
    ExInitializeFastMutex(&gBlockEntryLock);
    ExInitializeFastMutex(&gHashLookupGuardLock);
    gFileJournalHead = 0;
    gFileJournalCount = 0;
    gFileNextSequence = 1;
    gProtectedPathCount = 0;
    gBlockEntryCount = 0;
    gHashLookupGuardThreadCount = 0;
    RtlZeroMemory(gFileJournal, sizeof(gFileJournal));
    RtlZeroMemory(gProtectedPaths, sizeof(gProtectedPaths));
    RtlZeroMemory(gBlockEntries, sizeof(gBlockEntries));
    RtlZeroMemory(gHashLookupGuardThreads, sizeof(gHashLookupGuardThreads));

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
