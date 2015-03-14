// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements an entry point of the driver and initializes other
// components in this module.
//
#include "stdafx.h"
#include "log.h"

namespace stdexp = std::experimental;

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

static const wchar_t SCVNP_OUT_DIRECTORY_PATH[] = L"\\SystemRoot\\Scavenger";
static const wchar_t SCVNP_LOG_FILE_PATH[] =
    L"\\SystemRoot\\Scavenger\\Scavenger.log";

#if DBG
static const auto SCVNP_LOG_LEVEL = LOG_PUT_LEVEL_DEBUG;
#else
static const auto SCVNP_LOG_LEVEL = LOG_PUT_LEVEL_INFO;
#endif

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C NTKERNELAPI UCHAR *NTAPI
PsGetProcessImageFileName(_In_ PEPROCESS Process);

EXTERN_C DRIVER_INITIALIZE DriverEntry;

EXTERN_C static NTSTATUS ScvnpCreateDirectory(_In_ const wchar_t *PathW);

EXTERN_C static NTSTATUS FLTAPI ScvnpUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

EXTERN_C static FLT_POSTOP_CALLBACK_STATUS FLTAPI
ScvnpPostCleanupAndFlushBuffers(_Inout_ PFLT_CALLBACK_DATA Data,
                                _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                _In_opt_ PVOID CompletionContext,
                                _In_ FLT_POST_OPERATION_FLAGS Flags);

EXTERN_C static FLT_PREOP_CALLBACK_STATUS FLTAPI
ScvnpPreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data,
                       _In_ PCFLT_RELATED_OBJECTS FltObjects,
                       _Outptr_result_maybenull_ PVOID *CompletionContext);

EXTERN_C static NTSTATUS ScvnpScavenge(_Inout_ PFLT_CALLBACK_DATA Data,
                                       _In_ PCFLT_RELATED_OBJECTS FltObjects);

EXTERN_C static bool ScvnpIsWhiteListedFile(_In_ PUNICODE_STRING
                                                TargetFileName);

EXTERN_C static NTSTATUS ScvnpReadFile(_In_ PFLT_CALLBACK_DATA Data,
                                       _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                       _Out_ void *Buffer,
                                       _In_ SIZE_T BufferSize);

EXTERN_C static NTSTATUS ScvnpWriteFile(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                                        _In_ const wchar_t *OutPathW,
                                        _In_ void *Buffer,
                                        _In_ ULONG BufferSize,
                                        _In_ ULONG CreateDisposition);

EXTERN_C static NTSTATUS ScvnpGetSha1(_Out_ UCHAR(&Sha1Hash)[20],
                                      _In_ void *Data, _In_ SIZE_T DataSize);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

static PFLT_FILTER g_ScvnpFilterHandle = nullptr;
static BCRYPT_ALG_HANDLE g_ScvnpSha1AlgorithmHandle = nullptr;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

//
ALLOC_TEXT(INIT, DriverEntry)
EXTERN_C NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                              _In_ PUNICODE_STRING RegistryPath) {
  const FLT_OPERATION_REGISTRATION fltCallbacks[] = {
      {
       IRP_MJ_CLEANUP, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, nullptr,
       ScvnpPostCleanupAndFlushBuffers,
      },
      {
       IRP_MJ_FLUSH_BUFFERS, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
       nullptr, ScvnpPostCleanupAndFlushBuffers,
      },
      {IRP_MJ_SET_INFORMATION, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
       ScvnpPreSetInformation, nullptr},
      {IRP_MJ_OPERATION_END}};

  const FLT_REGISTRATION filterRegistration = {
      sizeof(filterRegistration),  //  Size
      FLT_REGISTRATION_VERSION,    //  Version
      0,                           //  Flags
      nullptr,                     //  Context
      fltCallbacks,                //  Operation callbacks
      ScvnpUnload,                 //  FilterUnload
      nullptr,                     //  InstanceSetup
      nullptr,                     //  InstanceQueryTeardown
      nullptr,                     //  InstanceTeardownStart
      nullptr,                     //  InstanceTeardownComplete
      nullptr,                     //  GenerateFileName
      nullptr,                     //  GenerateDestinationFileName
      nullptr,                     //  NormalizeNameComponent
  };

  PAGED_CODE();
  UNREFERENCED_PARAMETER(RegistryPath);
  // DBG_BREAK();

  auto status = ScvnpCreateDirectory(SCVNP_OUT_DIRECTORY_PATH);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Initialize the Log system
  status = LogInitialization(
      SCVNP_LOG_LEVEL | LOG_OPT_DISABLE_TIME | LOG_OPT_DISABLE_FUNCTION_NAME,
      SCVNP_LOG_FILE_PATH, nullptr);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  auto scopedLogTermination =
      stdexp::make_scope_exit([] { LogTermination(nullptr); });

  // Initialize the crypt APIs.
  status = BCryptOpenAlgorithmProvider(&g_ScvnpSha1AlgorithmHandle,
                                       BCRYPT_SHA1_ALGORITHM, nullptr, 0);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR("BCryptOpenAlgorithmProvider failed (%08x)", status);
    return status;
  }
  auto scopedBCryptCloseAlgorithmProvider = stdexp::make_scope_exit(
      [] { BCryptCloseAlgorithmProvider(g_ScvnpSha1AlgorithmHandle, 0); });

  // Register and start a mini filter driver
  status = FltRegisterFilter(DriverObject, &filterRegistration,
                             &g_ScvnpFilterHandle);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR("FltRegisterFilter failed (%08x)", status);
    return status;
  }
  auto scopedFltUnregisterFilter =
      stdexp::make_scope_exit([] { FltUnregisterFilter(g_ScvnpFilterHandle); });

  status = FltStartFiltering(g_ScvnpFilterHandle);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR("FltStartFiltering failed (%08x)", status);
    return status;
  }

  scopedFltUnregisterFilter.release();
  scopedBCryptCloseAlgorithmProvider.release();
  scopedLogTermination.release();
  LOG_INFO("Scavenger installed");
  return status;
}

// Create a directory
ALLOC_TEXT(INIT, ScvnpCreateDirectory)
EXTERN_C static NTSTATUS ScvnpCreateDirectory(_In_ const wchar_t *PathW) {
  PAGED_CODE();

  UNICODE_STRING path = {};
  RtlInitUnicodeString(&path, PathW);
  OBJECT_ATTRIBUTES objAttr = RTL_INIT_OBJECT_ATTRIBUTES(
      &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE);

  IO_STATUS_BLOCK ioStatus = {};
  HANDLE directory = nullptr;
  NTSTATUS status = ZwCreateFile(
      &directory, GENERIC_WRITE, &objAttr, &ioStatus, nullptr,
      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
      FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE, nullptr, 0);
  if (NT_SUCCESS(status)) {
    ZwClose(directory);
  }

  return status;
}

// An unload handler
ALLOC_TEXT(PAGED, ScvnpUnload)
EXTERN_C static NTSTATUS FLTAPI
ScvnpUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(Flags);

  FltUnregisterFilter(g_ScvnpFilterHandle);
  BCryptCloseAlgorithmProvider(g_ScvnpSha1AlgorithmHandle, 0);
  LogTermination(nullptr);

  return STATUS_SUCCESS;
}

// A handler for file flushing and closing
EXTERN_C static FLT_POSTOP_CALLBACK_STATUS FLTAPI
ScvnpPostCleanupAndFlushBuffers(_Inout_ PFLT_CALLBACK_DATA Data,
                                _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                _In_opt_ PVOID CompletionContext,
                                _In_ FLT_POST_OPERATION_FLAGS Flags) {
  UNREFERENCED_PARAMETER(CompletionContext);
  UNREFERENCED_PARAMETER(Flags);

  if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
    return FLT_POSTOP_FINISHED_PROCESSING;
  }

  if (!FltObjects->FileObject->WriteAccess) {
    return FLT_POSTOP_FINISHED_PROCESSING;
  }

  // Handle only write related operations
  ScvnpScavenge(Data, FltObjects);
  return FLT_POSTOP_FINISHED_PROCESSING;
}

//
EXTERN_C static FLT_PREOP_CALLBACK_STATUS FLTAPI
ScvnpPreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data,
                       _In_ PCFLT_RELATED_OBJECTS FltObjects,
                       _Outptr_result_maybenull_ PVOID *CompletionContext) {
  UNREFERENCED_PARAMETER(CompletionContext);

  if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }

  switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {
    case FileAllocationInformation:
    case FileEndOfFileInformation:
      // Handle setting a file size to zero.
      if (Data->Iopb->Parameters.SetFileInformation.Length ==
          sizeof(LARGE_INTEGER)) {
        const auto position = reinterpret_cast<LARGE_INTEGER *>(
            Data->Iopb->Parameters.SetFileInformation.InfoBuffer);
        if (position && position->QuadPart == 0) {
          ScvnpScavenge(Data, FltObjects);
        }
      }
      break;

    case FileDispositionInformation:
      // Handle deleting a file.
      ScvnpScavenge(Data, FltObjects);
      break;
    default:
      break;
  }

  return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

//
ALLOC_TEXT(PAGED, ScvnpScavenge)
EXTERN_C static NTSTATUS ScvnpScavenge(_Inout_ PFLT_CALLBACK_DATA Data,
                                       _In_ PCFLT_RELATED_OBJECTS FltObjects) {
  PAGED_CODE();

  // Ignore system threads. Thus, this program does not support activities of
  // kernel mode code.
  if (PsIsSystemThread(PsGetCurrentThread())) {
    return STATUS_SUCCESS;
  }

  const auto operationType = FltGetIrpName(Data->Iopb->MajorFunction);

  PFLT_FILE_NAME_INFORMATION fileNameInformation = nullptr;
  auto status = FltGetFileNameInformationUnsafe(
      FltObjects->FileObject, FltObjects->Instance, FLT_FILE_NAME_NORMALIZED,
      &fileNameInformation);
  if (!NT_SUCCESS(status)) {
    // This error is expected to happen and okay to ignore it.
    if (status != STATUS_FILE_DELETED) {
      LOG_ERROR_SAFE("%-25s : FltGetFileNameInformationUnsafe failed (%08x)",
                     operationType, status);
    }
    return status;
  }
  const auto scopedFltReleaseFileNameInformation =
      stdexp::make_scope_exit([fileNameInformation] {
        FltReleaseFileNameInformation(fileNameInformation);
      });
  status = FltParseFileNameInformation(fileNameInformation);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("%-25s : FltParseFileNameInformation failed (%08x) for %wZ",
                   operationType, status, &fileNameInformation->Name);
    return status;
  }

  // Ignore directories
  BOOLEAN isDirectory = FALSE;
  status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance,
                          &isDirectory);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("%-25s : FltIsDirectory failed (%08x) for %wZ",
                   operationType, status, &fileNameInformation->Name);
    return status;
  }
  if (isDirectory) {
    return status;
  }

  // Go through a white list
  if (ScvnpIsWhiteListedFile(&fileNameInformation->Name)) {
    return status;
  }

  // Get a file size (etc).
  FILE_STANDARD_INFORMATION fileInfo = {};
  status = FltQueryInformationFile(FltObjects->Instance, FltObjects->FileObject,
                                   &fileInfo, sizeof(fileInfo),
                                   FileStandardInformation, nullptr);
  if (!NT_SUCCESS(status)) {
    // This error is expected to happen and okay to ignore it.
    if (status != STATUS_FILE_DELETED) {
      LOG_ERROR_SAFE("%-25s : FltQueryInformationFile failed (%08x) for %wZ",
                     operationType, status, &fileNameInformation->Name);
    }
    return status;
  }

  // Ignore if the file is empty
  if (fileInfo.EndOfFile.QuadPart == 0) {
    return status;
  }

  // Ignore if the file size is greater than 4GB
  if (fileInfo.EndOfFile.HighPart != 0) {
    return STATUS_FILE_TOO_LARGE;
  }

  const auto targetFileSize = fileInfo.EndOfFile.LowPart;

  // Read entire contents of the file onto non paged memory. Thus, it may fail
  // to handle a file larger than the amount of available memory.
  const auto buffer = stdexp::make_unique_resource(
      FltAllocatePoolAlignedWithTag(FltObjects->Instance, NonPagedPool,
                                    targetFileSize, SCVN_POOL_TAG_NAME),
      [FltObjects](void *p) {
        if (p) {
          FltFreePoolAlignedWithTag(FltObjects->Instance, p,
                                    SCVN_POOL_TAG_NAME);
        }
      });
  if (!buffer) {
    LOG_ERROR_SAFE(
        "%-25s : FltAllocatePoolAlignedWithTag failed (%lu bytes) for %wZ",
        operationType, targetFileSize, &fileNameInformation->Name);
    return status;
  }
  status = ScvnpReadFile(Data, FltObjects, buffer.get(), targetFileSize);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("%-25s : ScvnpReadFile failed (%08x) for %wZ", operationType,
                   status, &fileNameInformation->Name);
    return status;
  }

  // Calculate SHA1 of the written data.
  UCHAR sha1Hash[20] = {};
  status = ScvnpGetSha1(sha1Hash, buffer.get(), targetFileSize);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("%-25s : ScvnpGetSha1 failed (%08x) for %wZ", operationType,
                   status, &fileNameInformation->Name);
    return status;
  }
  wchar_t sha1HashW[41] = {};
  for (auto i = 0; i < RTL_NUMBER_OF(sha1Hash); ++i) {
    const auto outW = sha1HashW + i * 2;
    RtlStringCchPrintfW(outW, 3, L"%02x", sha1Hash[i]);
  }

  // Copy the read file contents to the out put folder as <SHA1>.bin.
  wchar_t outPathW[260];
  status = RtlStringCchPrintfW(outPathW, RTL_NUMBER_OF(outPathW), L"%s\\%s.bin",
                               SCVNP_OUT_DIRECTORY_PATH, sha1HashW);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("%-25s : RtlStringCchPrintfW failed (%08x) for %wZ",
                   operationType, status, &fileNameInformation->Name);
    return status;
  }
  status = ScvnpWriteFile(FltObjects, outPathW, buffer.get(), targetFileSize,
                          FILE_CREATE);
  if (status == STATUS_OBJECT_NAME_COLLISION ||
      status == STATUS_DELETE_PENDING) {
    return STATUS_SUCCESS;
  }
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("%-25s : ScvnpWriteFile failed (%08x) for %wZ",
                   operationType, status, &fileNameInformation->Name);
    return status;
  }

  // Done
  LOG_INFO_SAFE("%-25s for %wZ (saved as %S, %lu bytes, %wZ)", operationType,
                &fileNameInformation->FinalComponent, sha1HashW, targetFileSize,
                &fileNameInformation->Name);
  return status;
}

// Return true when a file path is white listed.
ALLOC_TEXT(PAGED, ScvnpIsWhiteListedFile)
EXTERN_C static bool ScvnpIsWhiteListedFile(_In_ PUNICODE_STRING
                                                TargetFileName) {
  PAGED_CODE();

  UNICODE_STRING WHITE_LIST[] = {
      RTL_CONSTANT_STRING(
          L"\\DEVICE\\HARDDISKVOLUME?\\*"
          L"\\APPDATA\\LOCAL\\MICROSOFT\\WINDOWS\\EXPLORER\\THUMBCACHE_*.DB"),
  };

  for (auto i = 0; i < RTL_NUMBER_OF(WHITE_LIST); ++i) {
    if (FsRtlIsNameInExpression(&WHITE_LIST[i], TargetFileName, TRUE,
                                nullptr)) {
      return true;
    }
  }
  return false;
}

// Read contents of a file
ALLOC_TEXT(PAGED, ScvnpReadFile)
EXTERN_C static NTSTATUS ScvnpReadFile(_In_ PFLT_CALLBACK_DATA Data,
                                       _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                       _Out_ void *Buffer,
                                       _In_ SIZE_T BufferSize) {
  PAGED_CODE();

  // Use an existing file object when it is NOT IRP_MJ_CLEANUP.
  if (Data->Iopb->MajorFunction != IRP_MJ_CLEANUP) {
    LARGE_INTEGER byteOffset = {};
    auto status = FltReadFile(FltObjects->Instance, FltObjects->FileObject,
                              &byteOffset, BufferSize, Buffer,
                              FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
                              nullptr, nullptr, nullptr);
    if (!NT_SUCCESS(status)) {
      LOG_ERROR_SAFE("FltReadFile failed (%08x)", status);
      return status;
    }
    return status;
  }

  // Make a new file object since the file is already out of the current IO
  // path.
  PFLT_FILE_NAME_INFORMATION fileNameInformation = nullptr;
  auto status = FltGetFileNameInformationUnsafe(
      FltObjects->FileObject, FltObjects->Instance, FLT_FILE_NAME_NORMALIZED,
      &fileNameInformation);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  const auto scopedFltReleaseFileNameInformation =
      stdexp::make_scope_exit([fileNameInformation] {
        FltReleaseFileNameInformation(fileNameInformation);
      });

  OBJECT_ATTRIBUTES objAttr = RTL_INIT_OBJECT_ATTRIBUTES(
      &fileNameInformation->Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE);

  HANDLE fileHandle = nullptr;
  IO_STATUS_BLOCK ioStatus = {};
  status = FltCreateFile(
      FltObjects->Filter, FltObjects->Instance, &fileHandle, GENERIC_READ,
      &objAttr, &ioStatus, nullptr, FILE_ATTRIBUTE_NORMAL,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF,
      FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT |
          FILE_NON_DIRECTORY_FILE,
      nullptr, 0, 0);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("FltCreateFile failed (%08x) for %wZ", status,
                   &fileNameInformation->Name);
    return status;
  }
  const auto scopedFltClose =
      stdexp::make_scope_exit([fileHandle] { FltClose(fileHandle); });

  PFILE_OBJECT fileObject = nullptr;
  status = ObReferenceObjectByHandle(fileHandle, 0, nullptr, KernelMode,
                                     reinterpret_cast<void **>(&fileObject),
                                     nullptr);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("ObReferenceObjectByHandle failed (%08x) for %wZ", status,
                   &fileNameInformation->Name);
    return status;
  }
  const auto scopedObDereferenceObject = stdexp::make_scope_exit(
      [fileObject] { ObDereferenceObject(fileObject); });

  status = FltReadFile(FltObjects->Instance, fileObject, nullptr, BufferSize,
                       Buffer, 0, nullptr, nullptr, nullptr);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("FltReadFile failed (%08x) for %wZ", status,
                   &fileNameInformation->Name);
    return status;
  }
  return status;
}

// Write data to a file
ALLOC_TEXT(PAGED, ScvnpWriteFile)
EXTERN_C static NTSTATUS ScvnpWriteFile(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                                        _In_ const wchar_t *OutPathW,
                                        _In_ void *Buffer,
                                        _In_ ULONG BufferSize,
                                        _In_ ULONG CreateDisposition) {
  PAGED_CODE();

  UNICODE_STRING outPath = {};
  RtlInitUnicodeString(&outPath, OutPathW);
  OBJECT_ATTRIBUTES objAttr = RTL_INIT_OBJECT_ATTRIBUTES(
      &outPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE);

  HANDLE fileHandle = nullptr;
  IO_STATUS_BLOCK ioStatus = {};
  auto status = FltCreateFile(
      FltObjects->Filter, FltObjects->Instance, &fileHandle, GENERIC_WRITE,
      &objAttr, &ioStatus, nullptr, FILE_ATTRIBUTE_NORMAL, 0, CreateDisposition,
      FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT |
          FILE_NON_DIRECTORY_FILE,
      nullptr, 0, 0);
  if (status == STATUS_OBJECT_NAME_COLLISION ||
      status == STATUS_DELETE_PENDING) {
    return status;
  }
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("FltCreateFile failed (%08x) for %S", status, OutPathW);
    return status;
  }
  const auto scopedFltClose =
      stdexp::make_scope_exit([fileHandle] { FltClose(fileHandle); });

  PFILE_OBJECT fileObject = nullptr;
  status = ObReferenceObjectByHandle(fileHandle, 0, nullptr, KernelMode,
                                     reinterpret_cast<void **>(&fileObject),
                                     nullptr);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("ObReferenceObjectByHandle failed (%08x) for %S", status,
                   OutPathW);
    return status;
  }
  const auto scopedObDereferenceObject = stdexp::make_scope_exit(
      [fileObject] { ObDereferenceObject(fileObject); });

  status = FltWriteFile(FltObjects->Instance, fileObject, nullptr, BufferSize,
                        Buffer, 0, nullptr, nullptr, nullptr);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("FltWriteFile failed (%08x) for %S", status, OutPathW);
    return status;
  }
  return status;
}

// Calculate SHA1
ALLOC_TEXT(PAGED, ScvnpGetSha1)
EXTERN_C static NTSTATUS ScvnpGetSha1(_Out_ UCHAR(&Sha1Hash)[20],
                                      _In_ void *Data, _In_ SIZE_T DataSize) {
  PAGED_CODE();

  BCRYPT_HASH_HANDLE hashHandle = nullptr;
  auto status = BCryptCreateHash(g_ScvnpSha1AlgorithmHandle, &hashHandle,
                                 nullptr, 0, nullptr, 0, 0);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("BCryptCreateHash failed (%08x)", status);
    return status;
  }
  const auto scopedBCryptDestroyHash =
      stdexp::make_scope_exit([hashHandle] { BCryptDestroyHash(hashHandle); });

  status = BCryptHashData(hashHandle, static_cast<UCHAR *>(Data), DataSize, 0);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("BCryptHashData failed (%08x)", status);
    return status;
  }

  static_assert(sizeof(Sha1Hash) == 20, "Size check");
  status = BCryptFinishHash(hashHandle, Sha1Hash, sizeof(Sha1Hash), 0);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR_SAFE("BCryptFinishHash failed (%08x)", status);
    return status;
  }

  return status;
}
