#include <ntddk.h>
#include <ntstrsafe.h>

#include "../include/aegis_windows_driver_protocol.h"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD AegisDriverUnload;
DRIVER_DISPATCH AegisDriverCreateClose;
DRIVER_DISPATCH AegisDriverDeviceControl;
EX_CALLBACK_FUNCTION AegisRegistryCallback;

typedef struct _AEGIS_REGISTRY_VALUE_CAPTURE {
    ULONG ValueType;
    ULONG DataSize;
    BOOLEAN Present;
    BOOLEAN Truncated;
    UCHAR Data[AEGIS_REGISTRY_MAX_VALUE_DATA_BYTES];
} AEGIS_REGISTRY_VALUE_CAPTURE, *PAEGIS_REGISTRY_VALUE_CAPTURE;

static FAST_MUTEX gRegistryJournalLock;
static AEGIS_REGISTRY_EVENT_RECORD gRegistryJournal[AEGIS_REGISTRY_JOURNAL_CAPACITY];
static ULONG gRegistryJournalHead = 0;
static ULONG gRegistryJournalCount = 0;
static ULONG gRegistryNextSequence = 1;
static LARGE_INTEGER gRegistryCallbackCookie;
static BOOLEAN gRegistryCallbackRegistered = FALSE;

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
    PUNICODE_STRING object_name = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(callback_context);

    if (argument2 == NULL || argument1 == NULL) {
        return STATUS_SUCCESS;
    }

    notify_class = (REG_NOTIFY_CLASS)(ULONG_PTR)argument1;
    if (notify_class != RegNtPreSetValueKey && notify_class != RegNtPreDeleteValueKey) {
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

        status = CmCallbackGetKeyObjectIDEx(
            &gRegistryCallbackCookie,
            info->Object,
            NULL,
            &object_name,
            0
        );
        if (!NT_SUCCESS(status) || object_name == NULL) {
            return STATUS_SUCCESS;
        }

        AegisCopyUnicodeString(record.KeyPath, RTL_NUMBER_OF(record.KeyPath), object_name);
        AegisCopyUnicodeString(record.ValueName, RTL_NUMBER_OF(record.ValueName), info->ValueName);
        record.Operation = AEGIS_REGISTRY_OPERATION_SET;
        RtlZeroMemory(&old_capture, sizeof(old_capture));
        status = AegisQueryValueByPath(object_name, info->ValueName, &old_capture);
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

        CmCallbackReleaseKeyObjectIDEx(object_name);
        AegisJournalPush(&record);
    } else if (notify_class == RegNtPreDeleteValueKey) {
        PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)argument2;
        AEGIS_REGISTRY_VALUE_CAPTURE old_capture;

        if (info->Object == NULL) {
            return STATUS_SUCCESS;
        }

        status = CmCallbackGetKeyObjectIDEx(
            &gRegistryCallbackCookie,
            info->Object,
            NULL,
            &object_name,
            0
        );
        if (!NT_SUCCESS(status) || object_name == NULL) {
            return STATUS_SUCCESS;
        }

        AegisCopyUnicodeString(record.KeyPath, RTL_NUMBER_OF(record.KeyPath), object_name);
        AegisCopyUnicodeString(record.ValueName, RTL_NUMBER_OF(record.ValueName), info->ValueName);
        record.Operation = AEGIS_REGISTRY_OPERATION_DELETE;
        RtlZeroMemory(&old_capture, sizeof(old_capture));
        status = AegisQueryValueByPath(object_name, info->ValueName, &old_capture);
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

        CmCallbackReleaseKeyObjectIDEx(object_name);
        AegisJournalPush(&record);
    }

    return STATUS_SUCCESS;
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
                if (RtlEqualUnicodeString(&selector, &record_key_path, TRUE)) {
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
                    if (!RtlEqualUnicodeString(&selector, &record_key_path, TRUE)) {
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
    }

    AegisCompleteRequest(irp, status, information);
    return status;
}

_Use_decl_annotations_
VOID AegisDriverUnload(PDRIVER_OBJECT driver_object) {
    UNICODE_STRING dos_device_name;

    if (gRegistryCallbackRegistered) {
        CmUnRegisterCallback(gRegistryCallbackCookie);
        gRegistryCallbackRegistered = FALSE;
    }

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
    PDEVICE_OBJECT device_object = NULL;
    ULONG major_index;

    UNREFERENCED_PARAMETER(registry_path);

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    ExInitializeFastMutex(&gRegistryJournalLock);
    gRegistryJournalHead = 0;
    gRegistryJournalCount = 0;
    gRegistryNextSequence = 1;
    RtlZeroMemory(gRegistryJournal, sizeof(gRegistryJournal));

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

    device_object->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
