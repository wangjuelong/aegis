#include <ntddk.h>
#include <ntstrsafe.h>

#include "../include/aegis_windows_driver_protocol.h"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD AegisDriverUnload;
DRIVER_DISPATCH AegisDriverCreateClose;
DRIVER_DISPATCH AegisDriverDeviceControl;
EX_CALLBACK_FUNCTION AegisRegistryCallback;
OB_PREOP_CALLBACK_STATUS AegisProcessPreOperation(
    _In_ PVOID registration_context,
    _In_ POB_PRE_OPERATION_INFORMATION operation_information
);

#ifndef SystemCodeIntegrityInformation
#define SystemCodeIntegrityInformation 103UL
#endif

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001UL
#endif

#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002UL
#endif

#ifndef PROCESS_SET_SESSIONID
#define PROCESS_SET_SESSIONID 0x0004UL
#endif

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008UL
#endif

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010UL
#endif

#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020UL
#endif

#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE 0x0040UL
#endif

#ifndef PROCESS_CREATE_PROCESS
#define PROCESS_CREATE_PROCESS 0x0080UL
#endif

#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA 0x0100UL
#endif

#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION 0x0200UL
#endif

#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800UL
#endif

#ifndef PROCESS_SET_LIMITED_INFORMATION
#define PROCESS_SET_LIMITED_INFORMATION 0x2000UL
#endif

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;

NTSYSAPI
PVOID
NTAPI
RtlPcToFileHeader(
    _In_ PVOID pc_value,
    _Outptr_ PVOID* base_of_image
);

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG system_information_class,
    _Out_writes_bytes_to_opt_(system_information_length, *return_length) PVOID system_information,
    _In_ ULONG system_information_length,
    _Out_opt_ PULONG return_length
);

typedef struct _AEGIS_REGISTRY_VALUE_CAPTURE {
    ULONG ValueType;
    ULONG DataSize;
    BOOLEAN Present;
    BOOLEAN Truncated;
    UCHAR Data[AEGIS_REGISTRY_MAX_VALUE_DATA_BYTES];
} AEGIS_REGISTRY_VALUE_CAPTURE, *PAEGIS_REGISTRY_VALUE_CAPTURE;

static FAST_MUTEX gRegistryJournalLock;
static FAST_MUTEX gProtectedRegistryPathLock;
static AEGIS_REGISTRY_EVENT_RECORD gRegistryJournal[AEGIS_REGISTRY_JOURNAL_CAPACITY];
static WCHAR gProtectedRegistryPaths[AEGIS_REGISTRY_PROTECTED_PATH_CAPACITY]
                                   [AEGIS_REGISTRY_MAX_KEY_PATH_CHARS];
static ULONG gRegistryJournalHead = 0;
static ULONG gRegistryJournalCount = 0;
static ULONG gRegistryNextSequence = 1;
static ULONG gProtectedRegistryPathCount = 0;
static LARGE_INTEGER gRegistryCallbackCookie;
static BOOLEAN gRegistryCallbackRegistered = FALSE;
static KSPIN_LOCK gProtectedProcessLock;
static ULONG gProtectedProcessIds[AEGIS_PROCESS_PROTECTION_CAPACITY];
static ULONG gProtectedProcessCount = 0;
static PVOID gObRegistrationHandle = NULL;
static BOOLEAN gObCallbackRegistered = FALSE;

static VOID AegisCaptureBytes(
    _Out_writes_bytes_(destination_capacity) PUCHAR destination,
    _In_ ULONG destination_capacity,
    _Out_ PULONG captured_size,
    _Out_ PBOOLEAN truncated,
    _In_reads_bytes_opt_(source_size) const UCHAR* source,
    _In_ ULONG source_size
);

static VOID AegisCopyUnicodeString(
    _Out_writes_(destination_count) PWCHAR destination,
    _In_ SIZE_T destination_count,
    _In_opt_ PCUNICODE_STRING source
);

static NTSTATUS AegisCopyNormalizedUnicodeString(
    _Out_writes_(destination_count) PWCHAR destination,
    _In_ SIZE_T destination_count,
    _In_opt_ PCUNICODE_STRING source
);

static NTSTATUS AegisQueryValueByPath(
    _In_ PCUNICODE_STRING key_path,
    _In_opt_ PCUNICODE_STRING value_name,
    _Out_ PAEGIS_REGISTRY_VALUE_CAPTURE capture
);

static NTSTATUS AegisOpenKeyForRollback(
    _In_ PCUNICODE_STRING key_path,
    _Out_ PHANDLE key_handle
);

static NTSTATUS AegisApplyRollbackRecord(
    _In_ const AEGIS_REGISTRY_EVENT_RECORD* record
);

static VOID AegisJournalPush(
    _In_ const AEGIS_REGISTRY_EVENT_RECORD* record
);

static BOOLEAN AegisIsProtectedProcessId(
    _In_ ULONG process_id
);

static ULONG AegisProtectedProcessCount(VOID);

static NTSTATUS AegisProtectProcessId(
    _In_ ULONG process_id
);

static ULONG AegisProtectedRegistryPathCountUnlocked(VOID);

static ULONG AegisProtectedRegistryPathCount(VOID);

static VOID AegisClearProtectedRegistryPaths(VOID);

static NTSTATUS AegisProtectRegistryPath(
    _In_ PCUNICODE_STRING key_path
);

static BOOLEAN AegisRegistryPathMatchesSelector(
    _In_ PCUNICODE_STRING key_path,
    _In_ PCUNICODE_STRING selector
);

static BOOLEAN AegisIsProtectedRegistryPath(
    _In_ PCUNICODE_STRING key_path
);

static NTSTATUS AegisCaptureKeyPathFromObject(
    _In_ PVOID key_object,
    _Out_writes_(destination_count) PWCHAR destination,
    _In_ SIZE_T destination_count
);

static NTSTATUS AegisResolveRegistryPathFromRootAndName(
    _In_opt_ PVOID root_object,
    _In_opt_ PCUNICODE_STRING complete_name,
    _Out_writes_(destination_count) PWCHAR destination,
    _In_ SIZE_T destination_count
);

static ACCESS_MASK AegisStripProtectedProcessAccess(
    _In_ ACCESS_MASK desired_access
);

static VOID AegisPopulateIntegrityResponse(
    _Out_ PAEGIS_DRIVER_INTEGRITY_RESPONSE response
);

static BOOLEAN AegisInspectKernelRoutines(
    _Out_ PBOOLEAN suspicious
);

static BOOLEAN AegisQueryCodeIntegrityOptions(
    _Out_ PULONG code_integrity_options
);

static ULONG AegisJournalOldestSequenceUnlocked(VOID) {
    if (gRegistryJournalCount == 0) {
        return 0;
    }

    return gRegistryJournal[gRegistryJournalHead].Sequence;
}

static ULONG AegisJournalCurrentSequenceUnlocked(VOID) {
    if (gRegistryNextSequence == 0) {
        return 0;
    }

    return gRegistryNextSequence - 1;
}

static ULONG AegisProtectedRegistryPathCountUnlocked(VOID) {
    return gProtectedRegistryPathCount;
}

static ULONG AegisProtectedRegistryPathCount(VOID) {
    ULONG count;

    ExAcquireFastMutex(&gProtectedRegistryPathLock);
    count = AegisProtectedRegistryPathCountUnlocked();
    ExReleaseFastMutex(&gProtectedRegistryPathLock);
    return count;
}

static BOOLEAN AegisIsProtectedProcessId(
    _In_ ULONG process_id
) {
    KIRQL previous_irql;
    ULONG index;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&gProtectedProcessLock, &previous_irql);
    for (index = 0; index < gProtectedProcessCount; index++) {
        if (gProtectedProcessIds[index] == process_id) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&gProtectedProcessLock, previous_irql);
    return found;
}

static ULONG AegisProtectedProcessCount(VOID) {
    KIRQL previous_irql;
    ULONG count;

    KeAcquireSpinLock(&gProtectedProcessLock, &previous_irql);
    count = gProtectedProcessCount;
    KeReleaseSpinLock(&gProtectedProcessLock, previous_irql);
    return count;
}

static VOID AegisClearProtectedRegistryPaths(VOID) {
    ExAcquireFastMutex(&gProtectedRegistryPathLock);
    gProtectedRegistryPathCount = 0;
    RtlZeroMemory(gProtectedRegistryPaths, sizeof(gProtectedRegistryPaths));
    ExReleaseFastMutex(&gProtectedRegistryPathLock);
}

static NTSTATUS AegisProtectProcessId(
    _In_ ULONG process_id
) {
    KIRQL previous_irql;
    ULONG index;
    NTSTATUS status = STATUS_SUCCESS;

    if (process_id == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&gProtectedProcessLock, &previous_irql);
    for (index = 0; index < gProtectedProcessCount; index++) {
        if (gProtectedProcessIds[index] == process_id) {
            KeReleaseSpinLock(&gProtectedProcessLock, previous_irql);
            return STATUS_SUCCESS;
        }
    }

    if (gProtectedProcessCount >= AEGIS_PROCESS_PROTECTION_CAPACITY) {
        status = STATUS_INSUFFICIENT_RESOURCES;
    } else {
        gProtectedProcessIds[gProtectedProcessCount] = process_id;
        gProtectedProcessCount += 1;
    }
    KeReleaseSpinLock(&gProtectedProcessLock, previous_irql);

    return status;
}

static NTSTATUS AegisProtectRegistryPath(
    _In_ PCUNICODE_STRING key_path
) {
    WCHAR normalized_path[AEGIS_REGISTRY_MAX_KEY_PATH_CHARS];
    UNICODE_STRING candidate;
    KIRQL previous_irql;
    ULONG index;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(previous_irql);

    status = AegisCopyNormalizedUnicodeString(
        normalized_path,
        RTL_NUMBER_OF(normalized_path),
        key_path
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&candidate, normalized_path);
    if (candidate.Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireFastMutex(&gProtectedRegistryPathLock);
    for (index = 0; index < gProtectedRegistryPathCount; index++) {
        UNICODE_STRING existing;

        RtlInitUnicodeString(&existing, gProtectedRegistryPaths[index]);
        if (RtlEqualUnicodeString(&candidate, &existing, TRUE)) {
            ExReleaseFastMutex(&gProtectedRegistryPathLock);
            return STATUS_SUCCESS;
        }
    }

    if (gProtectedRegistryPathCount >= AEGIS_REGISTRY_PROTECTED_PATH_CAPACITY) {
        status = STATUS_INSUFFICIENT_RESOURCES;
    } else {
        RtlStringCchCopyW(
            gProtectedRegistryPaths[gProtectedRegistryPathCount],
            RTL_NUMBER_OF(gProtectedRegistryPaths[gProtectedRegistryPathCount]),
            normalized_path
        );
        gProtectedRegistryPathCount += 1;
    }
    ExReleaseFastMutex(&gProtectedRegistryPathLock);

    return status;
}

static ACCESS_MASK AegisStripProtectedProcessAccess(
    _In_ ACCESS_MASK desired_access
) {
    const ACCESS_MASK disallowed =
        PROCESS_TERMINATE |
        PROCESS_CREATE_THREAD |
        PROCESS_SET_SESSIONID |
        PROCESS_VM_OPERATION |
        PROCESS_VM_READ |
        PROCESS_VM_WRITE |
        PROCESS_DUP_HANDLE |
        PROCESS_CREATE_PROCESS |
        PROCESS_SET_QUOTA |
        PROCESS_SET_INFORMATION |
        PROCESS_SUSPEND_RESUME |
        PROCESS_SET_LIMITED_INFORMATION |
        DELETE |
        WRITE_DAC |
        WRITE_OWNER;

    return desired_access & ~disallowed;
}

static BOOLEAN AegisInspectKernelRoutines(
    _Out_ PBOOLEAN suspicious
) {
    static const PCWSTR routine_names[AEGIS_INTEGRITY_ROUTINE_COUNT] = {
        L"ZwClose",
        L"ZwOpenProcess",
        L"ZwTerminateProcess",
        L"ZwQueryInformationProcess"
    };
    UNICODE_STRING routine_name;
    PVOID expected_image_base = NULL;
    ULONG index;

    *suspicious = FALSE;

    for (index = 0; index < AEGIS_INTEGRITY_ROUTINE_COUNT; index++) {
        PVOID routine_address = NULL;
        PVOID image_base = NULL;

        RtlInitUnicodeString(&routine_name, routine_names[index]);
        routine_address = MmGetSystemRoutineAddress(&routine_name);
        if (routine_address == NULL) {
            return FALSE;
        }

        if (RtlPcToFileHeader(routine_address, &image_base) == NULL || image_base == NULL) {
            return FALSE;
        }

        if (expected_image_base == NULL) {
            expected_image_base = image_base;
        } else if (image_base != expected_image_base) {
            *suspicious = TRUE;
        }
    }

    return TRUE;
}

static BOOLEAN AegisQueryCodeIntegrityOptions(
    _Out_ PULONG code_integrity_options
) {
    SYSTEM_CODEINTEGRITY_INFORMATION code_integrity;
    NTSTATUS status;

    RtlZeroMemory(&code_integrity, sizeof(code_integrity));
    code_integrity.Length = sizeof(code_integrity);
    status = ZwQuerySystemInformation(
        SystemCodeIntegrityInformation,
        &code_integrity,
        sizeof(code_integrity),
        NULL
    );
    if (!NT_SUCCESS(status)) {
        *code_integrity_options = 0;
        return FALSE;
    }

    *code_integrity_options = code_integrity.CodeIntegrityOptions;
    return TRUE;
}

static VOID AegisPopulateIntegrityResponse(
    _Out_ PAEGIS_DRIVER_INTEGRITY_RESPONSE response
) {
    BOOLEAN ssdt_suspicious = FALSE;
    ULONG code_integrity_options = 0;

    RtlZeroMemory(response, sizeof(*response));
    response->ProtocolVersion = AEGIS_DRIVER_PROTOCOL_VERSION;
    response->ObCallbackRegistered = gObCallbackRegistered ? 1UL : 0UL;
    response->ProtectedProcessCount = AegisProtectedProcessCount();
    response->SsdtInspectionSucceeded =
        AegisInspectKernelRoutines(&ssdt_suspicious) ? 1UL : 0UL;
    response->SsdtSuspicious = ssdt_suspicious ? 1UL : 0UL;
    response->CallbackInspectionSucceeded = 1UL;
    response->CallbackSuspicious =
        (gRegistryCallbackRegistered && gObCallbackRegistered) ? 0UL : 1UL;
    response->KernelCodeInspectionSucceeded =
        AegisQueryCodeIntegrityOptions(&code_integrity_options) ? 1UL : 0UL;
    response->CodeIntegrityOptions = code_integrity_options;
    response->KernelCodeSuspicious =
        (response->KernelCodeInspectionSucceeded == 0) ||
        ((code_integrity_options & AEGIS_INTEGRITY_CODEINTEGRITY_OPTION_ENABLED) == 0 &&
         (code_integrity_options & AEGIS_INTEGRITY_CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) == 0) ||
        ((code_integrity_options & AEGIS_INTEGRITY_CODEINTEGRITY_OPTION_TESTSIGN) != 0)
            ? 1UL
            : 0UL;
}

static VOID AegisCompleteRequest(
    _Inout_ PIRP irp,
    _In_ NTSTATUS status,
    _In_ ULONG_PTR information
) {
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
}

static VOID AegisCaptureBytes(
    _Out_writes_bytes_(destination_capacity) PUCHAR destination,
    _In_ ULONG destination_capacity,
    _Out_ PULONG captured_size,
    _Out_ PBOOLEAN truncated,
    _In_reads_bytes_opt_(source_size) const UCHAR* source,
    _In_ ULONG source_size
) {
    ULONG copy_size = 0;

    *captured_size = 0;
    *truncated = FALSE;
    if (destination_capacity == 0 || destination == NULL || source == NULL || source_size == 0) {
        return;
    }

    copy_size = source_size;
    if (copy_size > destination_capacity) {
        copy_size = destination_capacity;
        *truncated = TRUE;
    }

    RtlCopyMemory(destination, source, copy_size);
    *captured_size = copy_size;
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

static NTSTATUS AegisCopyNormalizedUnicodeString(
    _Out_writes_(destination_count) PWCHAR destination,
    _In_ SIZE_T destination_count,
    _In_opt_ PCUNICODE_STRING source
) {
    SIZE_T copy_chars = 0;

    if (destination == NULL || destination_count == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(destination, destination_count * sizeof(WCHAR));
    if (source == NULL || source->Buffer == NULL || source->Length == 0) {
        return STATUS_SUCCESS;
    }

    copy_chars = source->Length / sizeof(WCHAR);
    if (copy_chars >= destination_count) {
        return STATUS_NAME_TOO_LONG;
    }

    if (copy_chars > 0) {
        RtlCopyMemory(destination, source->Buffer, copy_chars * sizeof(WCHAR));
    }
    destination[copy_chars] = UNICODE_NULL;

    while (copy_chars > 1 && destination[copy_chars - 1] == L'\\') {
        destination[copy_chars - 1] = UNICODE_NULL;
        copy_chars -= 1;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS AegisQueryValueByPath(
    _In_ PCUNICODE_STRING key_path,
    _In_opt_ PCUNICODE_STRING value_name,
    _Out_ PAEGIS_REGISTRY_VALUE_CAPTURE capture
) {
    OBJECT_ATTRIBUTES attributes;
    HANDLE key_handle = NULL;
    NTSTATUS status;
    ULONG required_length = 0;
    PKEY_VALUE_PARTIAL_INFORMATION value_information = NULL;
    UNICODE_STRING empty_value_name;
    PUNICODE_STRING value_name_to_query = (PUNICODE_STRING)value_name;

    RtlZeroMemory(capture, sizeof(*capture));
    RtlInitUnicodeString(&empty_value_name, L"");
    if (value_name_to_query == NULL) {
        value_name_to_query = &empty_value_name;
    }
    InitializeObjectAttributes(
        &attributes,
        (PUNICODE_STRING)key_path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    status = ZwOpenKey(&key_handle, KEY_QUERY_VALUE, &attributes);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ZwQueryValueKey(
        key_handle,
        value_name_to_query,
        KeyValuePartialInformation,
        NULL,
        0,
        &required_length
    );
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        ZwClose(key_handle);
        return status;
    }

    value_information = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(
        POOL_FLAG_PAGED,
        required_length,
        'grRA'
    );
    if (value_information == NULL) {
        ZwClose(key_handle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryValueKey(
        key_handle,
        value_name_to_query,
        KeyValuePartialInformation,
        value_information,
        required_length,
        &required_length
    );
    ZwClose(key_handle);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(value_information, 'grRA');
        return status;
    }

    capture->Present = TRUE;
    capture->ValueType = value_information->Type;
    AegisCaptureBytes(
        capture->Data,
        AEGIS_REGISTRY_MAX_VALUE_DATA_BYTES,
        &capture->DataSize,
        &capture->Truncated,
        value_information->Data,
        value_information->DataLength
    );

    ExFreePoolWithTag(value_information, 'grRA');
    return STATUS_SUCCESS;
}

static NTSTATUS AegisOpenKeyForRollback(
    _In_ PCUNICODE_STRING key_path,
    _Out_ PHANDLE key_handle
) {
    OBJECT_ATTRIBUTES attributes;

    InitializeObjectAttributes(
        &attributes,
        (PUNICODE_STRING)key_path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    return ZwOpenKey(key_handle, KEY_SET_VALUE | KEY_QUERY_VALUE, &attributes);
}

static BOOLEAN AegisRegistryPathMatchesSelector(
    _In_ PCUNICODE_STRING key_path,
    _In_ PCUNICODE_STRING selector
) {
    USHORT selector_chars;

    if (key_path == NULL || selector == NULL) {
        return FALSE;
    }
    if (!RtlPrefixUnicodeString(selector, key_path, TRUE)) {
        return FALSE;
    }
    if (key_path->Length == selector->Length) {
        return TRUE;
    }

    selector_chars = selector->Length / sizeof(WCHAR);
    return key_path->Buffer[selector_chars] == L'\\';
}

static BOOLEAN AegisIsProtectedRegistryPath(
    _In_ PCUNICODE_STRING key_path
) {
    WCHAR normalized_path[AEGIS_REGISTRY_MAX_KEY_PATH_CHARS];
    UNICODE_STRING candidate;
    ULONG index;
    BOOLEAN found = FALSE;

    if (!NT_SUCCESS(AegisCopyNormalizedUnicodeString(
            normalized_path,
            RTL_NUMBER_OF(normalized_path),
            key_path
        ))) {
        return FALSE;
    }

    RtlInitUnicodeString(&candidate, normalized_path);
    if (candidate.Length == 0) {
        return FALSE;
    }

    ExAcquireFastMutex(&gProtectedRegistryPathLock);
    for (index = 0; index < gProtectedRegistryPathCount; index++) {
        UNICODE_STRING selector;

        RtlInitUnicodeString(&selector, gProtectedRegistryPaths[index]);
        if (AegisRegistryPathMatchesSelector(&candidate, &selector)) {
            found = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&gProtectedRegistryPathLock);

    return found;
}

static NTSTATUS AegisCaptureKeyPathFromObject(
    _In_ PVOID key_object,
    _Out_writes_(destination_count) PWCHAR destination,
    _In_ SIZE_T destination_count
) {
    NTSTATUS status;
    PUNICODE_STRING object_name = NULL;

    if (key_object == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = CmCallbackGetKeyObjectIDEx(
        &gRegistryCallbackCookie,
        key_object,
        NULL,
        &object_name,
        0
    );
    if (!NT_SUCCESS(status) || object_name == NULL) {
        return status;
    }

    status = AegisCopyNormalizedUnicodeString(destination, destination_count, object_name);
    CmCallbackReleaseKeyObjectIDEx(object_name);
    return status;
}

static NTSTATUS AegisResolveRegistryPathFromRootAndName(
    _In_opt_ PVOID root_object,
    _In_opt_ PCUNICODE_STRING complete_name,
    _Out_writes_(destination_count) PWCHAR destination,
    _In_ SIZE_T destination_count
) {
    NTSTATUS status;
    size_t current_length = 0;

    if (destination == NULL || destination_count == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(destination, destination_count * sizeof(WCHAR));

    if (complete_name != NULL &&
        complete_name->Buffer != NULL &&
        complete_name->Length > 0 &&
        complete_name->Buffer[0] == L'\\') {
        return AegisCopyNormalizedUnicodeString(destination, destination_count, complete_name);
    }

    if (root_object == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = AegisCaptureKeyPathFromObject(root_object, destination, destination_count);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (complete_name == NULL || complete_name->Buffer == NULL || complete_name->Length == 0) {
        return STATUS_SUCCESS;
    }

    status = RtlStringCchLengthW(destination, destination_count, &current_length);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (current_length > 0 && destination[current_length - 1] != L'\\') {
        status = RtlStringCchCatW(destination, destination_count, L"\\");
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    status = RtlStringCchCatNW(
        destination,
        destination_count,
        complete_name->Buffer,
        complete_name->Length / sizeof(WCHAR)
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = RtlStringCchLengthW(destination, destination_count, &current_length);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    while (current_length > 1 && destination[current_length - 1] == L'\\') {
        destination[current_length - 1] = UNICODE_NULL;
        current_length -= 1;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS AegisApplyRollbackRecord(
    _In_ const AEGIS_REGISTRY_EVENT_RECORD* record
) {
    HANDLE key_handle = NULL;
    UNICODE_STRING key_path;
    UNICODE_STRING value_name;
    NTSTATUS status;

    if (record->OldDataTruncated) {
        return STATUS_BUFFER_OVERFLOW;
    }

    RtlInitUnicodeString(&key_path, record->KeyPath);
    status = AegisOpenKeyForRollback(&key_path, &key_handle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&value_name, record->ValueName);
    if (record->OldValuePresent == 0) {
        status = ZwDeleteValueKey(key_handle, &value_name);
        if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
            status = STATUS_SUCCESS;
        }
    } else {
        status = ZwSetValueKey(
            key_handle,
            &value_name,
            0,
            record->ValueType,
            (PVOID)record->OldData,
            record->OldDataSize
        );
    }

    ZwClose(key_handle);
    return status;
}

static VOID AegisJournalPush(
    _In_ const AEGIS_REGISTRY_EVENT_RECORD* record
) {
    ULONG slot;

    ExAcquireFastMutex(&gRegistryJournalLock);
    if (gRegistryJournalCount == AEGIS_REGISTRY_JOURNAL_CAPACITY) {
        slot = gRegistryJournalHead;
        gRegistryJournalHead = (gRegistryJournalHead + 1) % AEGIS_REGISTRY_JOURNAL_CAPACITY;
    } else {
        slot = (gRegistryJournalHead + gRegistryJournalCount) % AEGIS_REGISTRY_JOURNAL_CAPACITY;
        gRegistryJournalCount += 1;
    }

    gRegistryJournal[slot] = *record;
    gRegistryJournal[slot].Sequence = gRegistryNextSequence++;
    ExReleaseFastMutex(&gRegistryJournalLock);
}

_Use_decl_annotations_
NTSTATUS AegisRegistryCallback(PVOID callback_context, PVOID argument1, PVOID argument2) {
    REG_NOTIFY_CLASS notify_class;
    AEGIS_REGISTRY_EVENT_RECORD record;
    UNICODE_STRING key_path;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(callback_context);

    if (argument2 == NULL || argument1 == NULL) {
        return STATUS_SUCCESS;
    }

    notify_class = (REG_NOTIFY_CLASS)(ULONG_PTR)argument1;
    if (notify_class != RegNtPreSetValueKey &&
        notify_class != RegNtPreDeleteValueKey &&
        notify_class != RegNtPreCreateKeyEx &&
        notify_class != RegNtPreDeleteKey) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&record, sizeof(record));
    KeQuerySystemTime(&record.Timestamp);

    if (notify_class == RegNtPreSetValueKey) {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)argument2;
        AEGIS_REGISTRY_VALUE_CAPTURE old_capture;
        BOOLEAN new_truncated = FALSE;

        if (info->Object == NULL) {
            return STATUS_SUCCESS;
        }

        status = AegisCaptureKeyPathFromObject(
            info->Object,
            record.KeyPath,
            RTL_NUMBER_OF(record.KeyPath)
        );
        if (!NT_SUCCESS(status)) {
            return STATUS_SUCCESS;
        }

        AegisCopyUnicodeString(record.ValueName, RTL_NUMBER_OF(record.ValueName), info->ValueName);
        record.Operation = AEGIS_REGISTRY_OPERATION_SET_VALUE;
        record.Blocked = 0UL;
        RtlZeroMemory(&old_capture, sizeof(old_capture));
        RtlInitUnicodeString(&key_path, record.KeyPath);

        RtlZeroMemory(&old_capture, sizeof(old_capture));
        status = AegisQueryValueByPath(&key_path, info->ValueName, &old_capture);
        if (NT_SUCCESS(status)) {
            record.ValueType = old_capture.ValueType;
            record.OldValuePresent = old_capture.Present ? 1UL : 0UL;
            record.OldDataTruncated = old_capture.Truncated ? 1UL : 0UL;
            record.OldDataSize = old_capture.DataSize;
            if (old_capture.DataSize > 0) {
                RtlCopyMemory(record.OldData, old_capture.Data, old_capture.DataSize);
            }
        }

        record.NewValuePresent = 1UL;
        record.ValueType = info->Type;
        AegisCaptureBytes(
            record.NewData,
            AEGIS_REGISTRY_MAX_VALUE_DATA_BYTES,
            &record.NewDataSize,
            &new_truncated,
            (const UCHAR*)info->Data,
            info->DataSize
        );
        record.NewDataTruncated = new_truncated ? 1UL : 0UL;

        if (AegisIsProtectedRegistryPath(&key_path)) {
            record.Blocked = 1UL;
            AegisJournalPush(&record);
            return STATUS_ACCESS_DENIED;
        }

        AegisJournalPush(&record);
    } else if (notify_class == RegNtPreDeleteValueKey) {
        PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)argument2;
        AEGIS_REGISTRY_VALUE_CAPTURE old_capture;

        if (info->Object == NULL) {
            return STATUS_SUCCESS;
        }

        status = AegisCaptureKeyPathFromObject(
            info->Object,
            record.KeyPath,
            RTL_NUMBER_OF(record.KeyPath)
        );
        if (!NT_SUCCESS(status)) {
            return STATUS_SUCCESS;
        }

        AegisCopyUnicodeString(record.ValueName, RTL_NUMBER_OF(record.ValueName), info->ValueName);
        record.Operation = AEGIS_REGISTRY_OPERATION_DELETE_VALUE;
        record.Blocked = 0UL;
        RtlInitUnicodeString(&key_path, record.KeyPath);
        RtlZeroMemory(&old_capture, sizeof(old_capture));
        status = AegisQueryValueByPath(&key_path, info->ValueName, &old_capture);
        if (NT_SUCCESS(status)) {
            record.ValueType = old_capture.ValueType;
            record.OldValuePresent = old_capture.Present ? 1UL : 0UL;
            record.OldDataTruncated = old_capture.Truncated ? 1UL : 0UL;
            record.OldDataSize = old_capture.DataSize;
            if (old_capture.DataSize > 0) {
                RtlCopyMemory(record.OldData, old_capture.Data, old_capture.DataSize);
            }
        }

        record.NewValuePresent = 0UL;
        record.NewDataSize = 0UL;
        record.NewDataTruncated = 0UL;

        if (AegisIsProtectedRegistryPath(&key_path)) {
            record.Blocked = 1UL;
            AegisJournalPush(&record);
            return STATUS_ACCESS_DENIED;
        }

        AegisJournalPush(&record);
    } else if (notify_class == RegNtPreCreateKeyEx) {
        PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)argument2;

        status = AegisResolveRegistryPathFromRootAndName(
            info->RootObject,
            info->CompleteName,
            record.KeyPath,
            RTL_NUMBER_OF(record.KeyPath)
        );
        if (!NT_SUCCESS(status)) {
            return STATUS_SUCCESS;
        }

        record.Operation = AEGIS_REGISTRY_OPERATION_CREATE_KEY;
        record.Blocked = 0UL;
        RtlInitUnicodeString(&key_path, record.KeyPath);
        if (AegisIsProtectedRegistryPath(&key_path)) {
            record.Blocked = 1UL;
            AegisJournalPush(&record);
            return STATUS_ACCESS_DENIED;
        }

        AegisJournalPush(&record);
    } else if (notify_class == RegNtPreDeleteKey) {
        PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)argument2;

        if (info->Object == NULL) {
            return STATUS_SUCCESS;
        }

        status = AegisCaptureKeyPathFromObject(
            info->Object,
            record.KeyPath,
            RTL_NUMBER_OF(record.KeyPath)
        );
        if (!NT_SUCCESS(status)) {
            return STATUS_SUCCESS;
        }

        record.Operation = AEGIS_REGISTRY_OPERATION_DELETE_KEY;
        record.Blocked = 0UL;
        RtlInitUnicodeString(&key_path, record.KeyPath);
        if (AegisIsProtectedRegistryPath(&key_path)) {
            record.Blocked = 1UL;
            AegisJournalPush(&record);
            return STATUS_ACCESS_DENIED;
        }

        AegisJournalPush(&record);
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
OB_PREOP_CALLBACK_STATUS AegisProcessPreOperation(
    PVOID registration_context,
    POB_PRE_OPERATION_INFORMATION operation_information
) {
    ACCESS_MASK* desired_access = NULL;
    ACCESS_MASK stripped_access;
    ULONG protected_pid;
    ULONG current_pid;

    UNREFERENCED_PARAMETER(registration_context);

    if (operation_information == NULL || operation_information->Object == NULL) {
        return OB_PREOP_SUCCESS;
    }
    if (operation_information->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }
    if (operation_information->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    protected_pid = HandleToULong(PsGetProcessId((PEPROCESS)operation_information->Object));
    current_pid = HandleToULong(PsGetCurrentProcessId());
    if (protected_pid == 0 || protected_pid == current_pid) {
        return OB_PREOP_SUCCESS;
    }
    if (!AegisIsProtectedProcessId(protected_pid)) {
        return OB_PREOP_SUCCESS;
    }

    if (operation_information->Operation == OB_OPERATION_HANDLE_CREATE) {
        desired_access =
            &operation_information->Parameters->CreateHandleInformation.DesiredAccess;
    } else if (operation_information->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        desired_access =
            &operation_information->Parameters->DuplicateHandleInformation.DesiredAccess;
    } else {
        return OB_PREOP_SUCCESS;
    }

    stripped_access = AegisStripProtectedProcessAccess(*desired_access);
    *desired_access = stripped_access;
    return OB_PREOP_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS AegisDriverCreateClose(PDEVICE_OBJECT device_object, PIRP irp) {
    UNREFERENCED_PARAMETER(device_object);
    AegisCompleteRequest(irp, STATUS_SUCCESS, 0);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS AegisDriverDeviceControl(PDEVICE_OBJECT device_object, PIRP irp) {
    UNREFERENCED_PARAMETER(device_object);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    if (stack->Parameters.DeviceIoControl.IoControlCode == AEGIS_IOCTL_QUERY_VERSION) {
        const CHAR payload[] = AEGIS_DRIVER_QUERY_VERSION_JSON;
        const ULONG required_size = (ULONG)sizeof(payload);
        PVOID output_buffer = irp->AssociatedIrp.SystemBuffer;
        const ULONG output_length = stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (output_buffer == NULL) {
            status = STATUS_INVALID_USER_BUFFER;
        } else if (output_length < required_size) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            RtlCopyMemory(output_buffer, payload, required_size);
            status = STATUS_SUCCESS;
            information = required_size;
        }
    } else if (stack->Parameters.DeviceIoControl.IoControlCode == AEGIS_IOCTL_QUERY_STATUS) {
        PAEGIS_DRIVER_STATUS_RESPONSE response =
            (PAEGIS_DRIVER_STATUS_RESPONSE)irp->AssociatedIrp.SystemBuffer;

        if (response == NULL) {
            status = STATUS_INVALID_USER_BUFFER;
        } else if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(*response)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            ExAcquireFastMutex(&gRegistryJournalLock);
            response->ProtocolVersion = AEGIS_DRIVER_PROTOCOL_VERSION;
            response->RegistryCallbackRegistered = gRegistryCallbackRegistered ? 1UL : 0UL;
            response->JournalCapacity = AEGIS_REGISTRY_JOURNAL_CAPACITY;
            response->JournalCount = gRegistryJournalCount;
            response->OldestSequence = AegisJournalOldestSequenceUnlocked();
            response->CurrentSequence = AegisJournalCurrentSequenceUnlocked();
            ExReleaseFastMutex(&gRegistryJournalLock);
            response->ObCallbackRegistered = gObCallbackRegistered ? 1UL : 0UL;
            response->ProtectedProcessCount = AegisProtectedProcessCount();
            response->ProtectedRegistryPathCount = AegisProtectedRegistryPathCount();
            status = STATUS_SUCCESS;
            information = sizeof(*response);
        }
    } else if (stack->Parameters.DeviceIoControl.IoControlCode == AEGIS_IOCTL_QUERY_REGISTRY_EVENTS) {
        PAEGIS_REGISTRY_EVENT_QUERY_REQUEST request =
            (PAEGIS_REGISTRY_EVENT_QUERY_REQUEST)irp->AssociatedIrp.SystemBuffer;
        PAEGIS_REGISTRY_EVENT_QUERY_RESPONSE response =
            (PAEGIS_REGISTRY_EVENT_QUERY_RESPONSE)irp->AssociatedIrp.SystemBuffer;
        ULONG output_length = stack->Parameters.DeviceIoControl.OutputBufferLength;
        ULONG max_from_buffer;
        ULONG requested_max;
        ULONG response_index = 0;
        ULONG journal_index;
        ULONG available_bytes;

        if (request == NULL || response == NULL) {
            status = STATUS_INVALID_USER_BUFFER;
        } else if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(*request) ||
                   output_length < sizeof(*response)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else if (request->ProtocolVersion != AEGIS_DRIVER_PROTOCOL_VERSION) {
            status = STATUS_REVISION_MISMATCH;
        } else {
            available_bytes = output_length - sizeof(*response);
            max_from_buffer = available_bytes / sizeof(AEGIS_REGISTRY_EVENT_RECORD);
            requested_max = request->MaxEntries;
            if (requested_max == 0 || requested_max > max_from_buffer) {
                requested_max = max_from_buffer;
            }

            RtlZeroMemory(response, sizeof(*response));
            ExAcquireFastMutex(&gRegistryJournalLock);
            response->ProtocolVersion = AEGIS_DRIVER_PROTOCOL_VERSION;
            response->OldestSequence = AegisJournalOldestSequenceUnlocked();
            response->CurrentSequence = AegisJournalCurrentSequenceUnlocked();
            if (request->LastSequence != 0 &&
                response->OldestSequence != 0 &&
                request->LastSequence + 1 < response->OldestSequence) {
                response->Overflowed = 1;
            }

            for (journal_index = 0; journal_index < gRegistryJournalCount; journal_index++) {
                ULONG slot = (gRegistryJournalHead + journal_index) % AEGIS_REGISTRY_JOURNAL_CAPACITY;
                if (gRegistryJournal[slot].Sequence <= request->LastSequence) {
                    continue;
                }
                if (response_index >= requested_max) {
                    break;
                }

                ((PAEGIS_REGISTRY_EVENT_RECORD)(response + 1))[response_index] =
                    gRegistryJournal[slot];
                response_index += 1;
            }
            response->ReturnedCount = response_index;
            ExReleaseFastMutex(&gRegistryJournalLock);
            status = STATUS_SUCCESS;
            information = sizeof(*response) + (response_index * sizeof(AEGIS_REGISTRY_EVENT_RECORD));
        }
    } else if (stack->Parameters.DeviceIoControl.IoControlCode == AEGIS_IOCTL_ROLLBACK_REGISTRY_KEY) {
        PAEGIS_REGISTRY_ROLLBACK_REQUEST request =
            (PAEGIS_REGISTRY_ROLLBACK_REQUEST)irp->AssociatedIrp.SystemBuffer;
        PAEGIS_REGISTRY_ROLLBACK_RESPONSE response =
            (PAEGIS_REGISTRY_ROLLBACK_RESPONSE)irp->AssociatedIrp.SystemBuffer;
        AEGIS_REGISTRY_EVENT_RECORD* matches = NULL;
        ULONG match_count = 0;
        ULONG journal_index;
        UNICODE_STRING selector;

        if (request == NULL || response == NULL) {
            status = STATUS_INVALID_USER_BUFFER;
        } else if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(*request) ||
                   stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(*response)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else if (request->ProtocolVersion != AEGIS_DRIVER_PROTOCOL_VERSION) {
            status = STATUS_REVISION_MISMATCH;
        } else if (request->KeyPath[0] == UNICODE_NULL) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            RtlInitUnicodeString(&selector, request->KeyPath);
            ExAcquireFastMutex(&gRegistryJournalLock);
            for (journal_index = 0; journal_index < gRegistryJournalCount; journal_index++) {
                ULONG reverse_slot =
                    (gRegistryJournalHead + gRegistryJournalCount - 1 - journal_index) %
                    AEGIS_REGISTRY_JOURNAL_CAPACITY;
                UNICODE_STRING record_key_path;
                RtlInitUnicodeString(&record_key_path, gRegistryJournal[reverse_slot].KeyPath);
                if (gRegistryJournal[reverse_slot].Blocked == 0 &&
                    (gRegistryJournal[reverse_slot].Operation == AEGIS_REGISTRY_OPERATION_SET_VALUE ||
                     gRegistryJournal[reverse_slot].Operation == AEGIS_REGISTRY_OPERATION_DELETE_VALUE) &&
                    RtlEqualUnicodeString(&selector, &record_key_path, TRUE)) {
                    match_count += 1;
                }
            }

            if (match_count > 0) {
                matches = (AEGIS_REGISTRY_EVENT_RECORD*)ExAllocatePool2(
                    POOL_FLAG_PAGED,
                    sizeof(AEGIS_REGISTRY_EVENT_RECORD) * match_count,
                    'bkRA'
                );
            }

            if (match_count > 0 && matches == NULL) {
                ExReleaseFastMutex(&gRegistryJournalLock);
                status = STATUS_INSUFFICIENT_RESOURCES;
            } else {
                ULONG copy_index = 0;
                for (journal_index = 0; journal_index < gRegistryJournalCount; journal_index++) {
                    ULONG reverse_slot =
                        (gRegistryJournalHead + gRegistryJournalCount - 1 - journal_index) %
                        AEGIS_REGISTRY_JOURNAL_CAPACITY;
                    UNICODE_STRING record_key_path;
                    BOOLEAN seen_value = FALSE;
                    ULONG existing_index;
                    RtlInitUnicodeString(&record_key_path, gRegistryJournal[reverse_slot].KeyPath);
                    if (gRegistryJournal[reverse_slot].Blocked != 0 ||
                        (gRegistryJournal[reverse_slot].Operation != AEGIS_REGISTRY_OPERATION_SET_VALUE &&
                         gRegistryJournal[reverse_slot].Operation != AEGIS_REGISTRY_OPERATION_DELETE_VALUE) ||
                        !RtlEqualUnicodeString(&selector, &record_key_path, TRUE)) {
                        continue;
                    }

                    for (existing_index = 0; existing_index < copy_index; existing_index++) {
                        UNICODE_STRING existing_value_name;
                        UNICODE_STRING record_value_name;
                        RtlInitUnicodeString(&existing_value_name, matches[existing_index].ValueName);
                        RtlInitUnicodeString(&record_value_name, gRegistryJournal[reverse_slot].ValueName);
                        if (RtlEqualUnicodeString(&existing_value_name, &record_value_name, TRUE)) {
                            seen_value = TRUE;
                            break;
                        }
                    }

                    if (!seen_value) {
                        matches[copy_index++] = gRegistryJournal[reverse_slot];
                    }
                }
                match_count = copy_index;
                ExReleaseFastMutex(&gRegistryJournalLock);

                RtlZeroMemory(response, sizeof(*response));
                response->ProtocolVersion = AEGIS_DRIVER_PROTOCOL_VERSION;
                status = STATUS_SUCCESS;
                for (journal_index = 0; journal_index < match_count; journal_index++) {
                    status = AegisApplyRollbackRecord(&matches[journal_index]);
                    if (!NT_SUCCESS(status)) {
                        break;
                    }
                    response->AppliedCount += 1;
                }

                ExAcquireFastMutex(&gRegistryJournalLock);
                response->CurrentSequence = AegisJournalCurrentSequenceUnlocked();
                ExReleaseFastMutex(&gRegistryJournalLock);

                if (matches != NULL) {
                    ExFreePoolWithTag(matches, 'bkRA');
                }

                if (NT_SUCCESS(status)) {
                    status = STATUS_SUCCESS;
                    information = sizeof(*response);
                }
            }
        }
    } else if (stack->Parameters.DeviceIoControl.IoControlCode == AEGIS_IOCTL_PROTECT_REGISTRY_PATH ||
               stack->Parameters.DeviceIoControl.IoControlCode == AEGIS_IOCTL_CLEAR_PROTECTED_REGISTRY_PATHS) {
        PAEGIS_REGISTRY_PROTECT_REQUEST request =
            (PAEGIS_REGISTRY_PROTECT_REQUEST)irp->AssociatedIrp.SystemBuffer;
        PAEGIS_REGISTRY_PROTECT_RESPONSE response =
            (PAEGIS_REGISTRY_PROTECT_RESPONSE)irp->AssociatedIrp.SystemBuffer;

        if (request == NULL || response == NULL) {
            status = STATUS_INVALID_USER_BUFFER;
        } else if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(*request) ||
                   stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(*response)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else if (request->ProtocolVersion != AEGIS_DRIVER_PROTOCOL_VERSION) {
            status = STATUS_REVISION_MISMATCH;
        } else if (stack->Parameters.DeviceIoControl.IoControlCode == AEGIS_IOCTL_PROTECT_REGISTRY_PATH) {
            UNICODE_STRING key_path;

            RtlInitUnicodeString(&key_path, request->KeyPath);
            status = AegisProtectRegistryPath(&key_path);
            if (NT_SUCCESS(status)) {
                RtlZeroMemory(response, sizeof(*response));
                response->ProtocolVersion = AEGIS_DRIVER_PROTOCOL_VERSION;
                response->ProtectedPathCount = AegisProtectedRegistryPathCount();
                information = sizeof(*response);
            }
        } else {
            AegisClearProtectedRegistryPaths();
            RtlZeroMemory(response, sizeof(*response));
            response->ProtocolVersion = AEGIS_DRIVER_PROTOCOL_VERSION;
            response->ProtectedPathCount = AegisProtectedRegistryPathCount();
            status = STATUS_SUCCESS;
            information = sizeof(*response);
        }
    } else if (stack->Parameters.DeviceIoControl.IoControlCode == AEGIS_IOCTL_PROTECT_PROCESS) {
        PAEGIS_PROCESS_PROTECT_REQUEST request =
            (PAEGIS_PROCESS_PROTECT_REQUEST)irp->AssociatedIrp.SystemBuffer;
        PAEGIS_PROCESS_PROTECT_RESPONSE response =
            (PAEGIS_PROCESS_PROTECT_RESPONSE)irp->AssociatedIrp.SystemBuffer;

        if (request == NULL || response == NULL) {
            status = STATUS_INVALID_USER_BUFFER;
        } else if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(*request) ||
                   stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(*response)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else if (request->ProtocolVersion != AEGIS_DRIVER_PROTOCOL_VERSION) {
            status = STATUS_REVISION_MISMATCH;
        } else {
            status = AegisProtectProcessId(request->ProcessId);
            if (NT_SUCCESS(status)) {
                RtlZeroMemory(response, sizeof(*response));
                response->ProtocolVersion = AEGIS_DRIVER_PROTOCOL_VERSION;
                response->ObCallbackRegistered = gObCallbackRegistered ? 1UL : 0UL;
                response->ProtectedProcessCount = AegisProtectedProcessCount();
                information = sizeof(*response);
            }
        }
    } else if (stack->Parameters.DeviceIoControl.IoControlCode == AEGIS_IOCTL_QUERY_INTEGRITY) {
        PAEGIS_DRIVER_INTEGRITY_RESPONSE response =
            (PAEGIS_DRIVER_INTEGRITY_RESPONSE)irp->AssociatedIrp.SystemBuffer;

        if (response == NULL) {
            status = STATUS_INVALID_USER_BUFFER;
        } else if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(*response)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            AegisPopulateIntegrityResponse(response);
            status = STATUS_SUCCESS;
            information = sizeof(*response);
        }
    }

    AegisCompleteRequest(irp, status, information);
    return status;
}

_Use_decl_annotations_
VOID AegisDriverUnload(PDRIVER_OBJECT driver_object) {
    UNICODE_STRING dos_device_name;

    if (gObRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(gObRegistrationHandle);
        gObRegistrationHandle = NULL;
        gObCallbackRegistered = FALSE;
    }
    if (gRegistryCallbackRegistered) {
        CmUnRegisterCallback(gRegistryCallbackCookie);
        gRegistryCallbackRegistered = FALSE;
    }
    AegisClearProtectedRegistryPaths();

    RtlInitUnicodeString(&dos_device_name, AEGIS_DRIVER_DOS_DEVICE_NAME_W);
    IoDeleteSymbolicLink(&dos_device_name);

    if (driver_object->DeviceObject != NULL) {
        IoDeleteDevice(driver_object->DeviceObject);
    }
}

_Use_decl_annotations_
NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
    NTSTATUS status;
    UNICODE_STRING nt_device_name;
    UNICODE_STRING dos_device_name;
    UNICODE_STRING altitude;
    UNICODE_STRING ob_altitude;
    PDEVICE_OBJECT device_object = NULL;
    OB_OPERATION_REGISTRATION operation_registration;
    OB_CALLBACK_REGISTRATION callback_registration;
    ULONG major_index;

    UNREFERENCED_PARAMETER(registry_path);

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    ExInitializeFastMutex(&gRegistryJournalLock);
    ExInitializeFastMutex(&gProtectedRegistryPathLock);
    KeInitializeSpinLock(&gProtectedProcessLock);
    gRegistryJournalHead = 0;
    gRegistryJournalCount = 0;
    gRegistryNextSequence = 1;
    gProtectedRegistryPathCount = 0;
    gProtectedProcessCount = 0;
    RtlZeroMemory(gProtectedProcessIds, sizeof(gProtectedProcessIds));
    RtlZeroMemory(gRegistryJournal, sizeof(gRegistryJournal));
    RtlZeroMemory(gProtectedRegistryPaths, sizeof(gProtectedRegistryPaths));

    for (major_index = 0; major_index <= IRP_MJ_MAXIMUM_FUNCTION; major_index++) {
        driver_object->MajorFunction[major_index] = AegisDriverCreateClose;
    }
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AegisDriverDeviceControl;
    driver_object->DriverUnload = AegisDriverUnload;

    RtlInitUnicodeString(&nt_device_name, AEGIS_DRIVER_NT_DEVICE_NAME_W);
    status = IoCreateDevice(
        driver_object,
        0,
        &nt_device_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &device_object
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    device_object->Flags |= DO_BUFFERED_IO;

    RtlInitUnicodeString(&dos_device_name, AEGIS_DRIVER_DOS_DEVICE_NAME_W);
    status = IoCreateSymbolicLink(&dos_device_name, &nt_device_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device_object);
        return status;
    }

    RtlInitUnicodeString(&altitude, AEGIS_DRIVER_REGISTRY_ALTITUDE_W);
    status = CmRegisterCallbackEx(
        AegisRegistryCallback,
        &altitude,
        driver_object,
        NULL,
        &gRegistryCallbackCookie,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&dos_device_name);
        IoDeleteDevice(device_object);
        return status;
    }
    gRegistryCallbackRegistered = TRUE;

    RtlZeroMemory(&operation_registration, sizeof(operation_registration));
    operation_registration.ObjectType = PsProcessType;
    operation_registration.Operations =
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operation_registration.PreOperation = AegisProcessPreOperation;
    operation_registration.PostOperation = NULL;

    RtlZeroMemory(&callback_registration, sizeof(callback_registration));
    RtlInitUnicodeString(&ob_altitude, AEGIS_DRIVER_PROCESS_PROTECTION_ALTITUDE_W);
    callback_registration.Version = OB_FLT_REGISTRATION_VERSION;
    callback_registration.OperationRegistrationCount = 1;
    callback_registration.RegistrationContext = NULL;
    callback_registration.Altitude = ob_altitude;
    callback_registration.OperationRegistration = &operation_registration;
    status = ObRegisterCallbacks(&callback_registration, &gObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        CmUnRegisterCallback(gRegistryCallbackCookie);
        gRegistryCallbackRegistered = FALSE;
        IoDeleteSymbolicLink(&dos_device_name);
        IoDeleteDevice(device_object);
        return status;
    }
    gObCallbackRegistered = TRUE;

    device_object->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
