#include <ntddk.h>

#include "../include/aegis_windows_driver_protocol.h"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD AegisDriverUnload;
DRIVER_DISPATCH AegisDriverCreateClose;
DRIVER_DISPATCH AegisDriverDeviceControl;

static VOID AegisCompleteRequest(
    _Inout_ PIRP irp,
    _In_ NTSTATUS status,
    _In_ ULONG_PTR information
) {
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
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
    }

    AegisCompleteRequest(irp, status, information);
    return status;
}

_Use_decl_annotations_
VOID AegisDriverUnload(PDRIVER_OBJECT driver_object) {
    UNICODE_STRING dos_device_name;

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
    PDEVICE_OBJECT device_object = NULL;
    ULONG major_index;

    UNREFERENCED_PARAMETER(registry_path);

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

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

    device_object->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
