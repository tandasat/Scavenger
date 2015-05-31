// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements logging functions.
//
#include "stdafx.h"
#include "log.h"

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constant and macro
//

// A size for log buffer in NonPagedPool. Two buffers are allocated with this
// size. Exceeded logs are ignored silently. Make it bigger if a buffered log
// size often reach this size.
static const auto LOGP_BUFFER_SIZE_IN_PAGES = 5ul;

// An actual log buffer size in bytes.
static const auto LOGP_BUFFER_SIZE = PAGE_SIZE * LOGP_BUFFER_SIZE_IN_PAGES;

// A size that is usable for logging. Minus one because the last byte is kept
// for \0.
static const auto LOGP_BUFFER_USABLE_SIZE = LOGP_BUFFER_SIZE - 1;

// An interval to flush buffered log entries into a log file.
static const auto LOGP_AUTO_FLUSH_INTERVAL_MSEC = 50;

static const ULONG LOGP_POOL_TAG_NAME = ' gol';

////////////////////////////////////////////////////////////////////////////////
//
// types
//

struct LogBufferInfo {
  volatile char *LogBufferHead;  // A pointer to a buffer currently used.
                                 // It is either LogBuffer1 or LogBuffer2.
  volatile char *LogBufferTail;  // A pointer to where the next log should
                                 // be written.
  char *LogBuffer1;
  char *LogBuffer2;
  SIZE_T LogMaximumUsage;  // Holds the biggest buffer usage to
                           // determine a necessary buffer size.
  HANDLE LogFileHandle;
  KSPIN_LOCK SpinLock;
  ERESOURCE Resource;
  volatile bool BufferFlushThreadShouldBeAlive;
  HANDLE BufferFlushThreadHandle;
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

EXTERN_C NTKERNELAPI UCHAR *NTAPI
PsGetProcessImageFileName(_In_ PEPROCESS Process);

EXTERN_C static NTSTATUS LogpInitializeBufferInfo(
    _In_ const wchar_t *LogFilePath, _In_opt_ PDEVICE_OBJECT DeviceObject,
    _Inout_ LogBufferInfo *Info);

EXTERN_C static void LogpFinalizeBufferInfo(_In_opt_ PDEVICE_OBJECT
                                                DeviceObject,
                                            _In_ LogBufferInfo *Info);

#ifdef _X86_
_Requires_lock_not_held_(*SpinLock) _Acquires_lock_(*SpinLock)
    _IRQL_requires_max_(DISPATCH_LEVEL) _IRQL_saves_
    _IRQL_raises_(DISPATCH_LEVEL) inline KIRQL
    KeAcquireSpinLockRaiseToDpc(_Inout_ PKSPIN_LOCK SpinLock);
#endif

EXTERN_C static NTSTATUS LogpMakePrefix(_In_ ULONG Level,
                                        _In_ const char *FunctionName,
                                        _In_ const char *LogMessage,
                                        _Out_ char *LogBuffer,
                                        _In_ size_t LogBufferLength);

EXTERN_C static const char *LogpFindBaseFunctionName(
    _In_ const char *FunctionName);

EXTERN_C static NTSTATUS LogpPut(_In_ const char *Message,
                                 _In_ ULONG Attribute);

EXTERN_C static NTSTATUS LogpWriteLogBufferToFile(_In_opt_ LogBufferInfo *Info);

EXTERN_C static NTSTATUS LogpWriteMessageToFile(_In_ const char *Message,
                                                _In_ const LogBufferInfo &Info);

EXTERN_C static NTSTATUS LogpBufferMessage(_In_ const char *Message,
                                           _In_opt_ LogBufferInfo *Info);

EXTERN_C static bool LogpIsLogFileEnabled(_In_ const LogBufferInfo &Info);

EXTERN_C static bool LogpIsLogNeeded(_In_ ULONG Level);

EXTERN_C static KSTART_ROUTINE LogpBufferFlushThreadRoutine;

EXTERN_C static NTSTATUS LogpSleep(_In_ LONG Millisecond);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

static auto g_LogpDebugFlag = LOG_PUT_LEVEL_DISABLE;
static LogBufferInfo g_LogpLogBufferInfo = {};

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

ALLOC_TEXT(INIT, LogInitialization)
EXTERN_C NTSTATUS LogInitialization(_In_ ULONG Flag,
                                    _In_opt_ const wchar_t *LogFilePath,
                                    _In_opt_ PDEVICE_OBJECT DeviceObject) {
  PAGED_CODE();

  auto status = STATUS_SUCCESS;

  g_LogpDebugFlag = Flag;

  if (DeviceObject && !LogFilePath) {
    return STATUS_INVALID_PARAMETER;
  }

  // Initialize a log file if a log file path is specified.
  if (LogFilePath) {
    status = LogpInitializeBufferInfo(LogFilePath, DeviceObject,
                                      &g_LogpLogBufferInfo);
    if (!NT_SUCCESS(status)) {
      return status;
    }
  }

  // Test the log.
  status = LOG_INFO(
      "Log system was initialized (Flag= %08x, Buffer= %p %p, File= %S).", Flag,
      g_LogpLogBufferInfo.LogBuffer1, g_LogpLogBufferInfo.LogBuffer2,
      LogFilePath);
  if (!NT_SUCCESS(status)) {
    goto Fail;
  }
  return status;

Fail:
  if (LogFilePath) {
    LogpFinalizeBufferInfo(DeviceObject, &g_LogpLogBufferInfo);
  }
  return status;
}

// Initialize a log file related code such as a flushing thread.
ALLOC_TEXT(INIT, LogpInitializeBufferInfo)
EXTERN_C static NTSTATUS LogpInitializeBufferInfo(
    _In_ const wchar_t *LogFilePath, _In_opt_ PDEVICE_OBJECT DeviceObject,
    _Inout_ LogBufferInfo *Info) {
  NT_ASSERT(LogFilePath);
  NT_ASSERT(Info);

  KeInitializeSpinLock(&Info->SpinLock);

  auto status = ExInitializeResourceLite(&Info->Resource);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  if (DeviceObject) {
    // We can handle IRP_MJ_SHUTDOWN in order to flush buffered log entries.
    status = IoRegisterShutdownNotification(DeviceObject);
    if (!NT_SUCCESS(status)) {
      LogpFinalizeBufferInfo(DeviceObject, Info);
      return status;
    }
  }

  // Allocate two log buffers on NonPagedPool.
  Info->LogBuffer1 = reinterpret_cast<char *>(ExAllocatePoolWithTag(
      NonPagedPool, LOGP_BUFFER_SIZE, LOGP_POOL_TAG_NAME));
  if (!Info->LogBuffer1) {
    LogpFinalizeBufferInfo(DeviceObject, Info);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  Info->LogBuffer2 = reinterpret_cast<char *>(ExAllocatePoolWithTag(
      NonPagedPool, LOGP_BUFFER_SIZE, LOGP_POOL_TAG_NAME));
  if (!Info->LogBuffer2) {
    LogpFinalizeBufferInfo(DeviceObject, Info);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  // Initialize these buffers
  RtlFillMemory(Info->LogBuffer1, LOGP_BUFFER_SIZE, 0xff);  // for debug
  Info->LogBuffer1[0] = '\0';
  Info->LogBuffer1[LOGP_BUFFER_SIZE - 1] = '\0';  // at the end

  RtlFillMemory(Info->LogBuffer2, LOGP_BUFFER_SIZE, 0xff);  // for debug
  Info->LogBuffer2[0] = '\0';
  Info->LogBuffer2[LOGP_BUFFER_SIZE - 1] = '\0';  // at the end

  // Buffer should be used is LogBuffer1, and location should be written logs
  // is the head of the buffer.
  Info->LogBufferHead = Info->LogBuffer1;
  Info->LogBufferTail = Info->LogBuffer1;

  // Initialize a log file
  UNICODE_STRING logFilePathU = {};
  RtlInitUnicodeString(&logFilePathU, LogFilePath);

  OBJECT_ATTRIBUTES oa = {};
  InitializeObjectAttributes(&oa, &logFilePathU,
                             OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr,
                             nullptr);

  IO_STATUS_BLOCK ioStatus = {};
  status = ZwCreateFile(
      &Info->LogFileHandle, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &ioStatus,
      nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
      FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, nullptr, 0);
  if (!NT_SUCCESS(status)) {
    LogpFinalizeBufferInfo(DeviceObject, Info);
    return status;
  }

  // Initialize a log buffer flush thread.
  Info->BufferFlushThreadShouldBeAlive = true;
  status = PsCreateSystemThread(&Info->BufferFlushThreadHandle, GENERIC_ALL,
                                nullptr, nullptr, nullptr,
                                LogpBufferFlushThreadRoutine, Info);
  if (!NT_SUCCESS(status)) {
    LogpFinalizeBufferInfo(DeviceObject, Info);
    return status;
  }

  return status;
}

// Terminates the log functions without releasing resources.
ALLOC_TEXT(PAGED, LogIrpShutdownHandler)
EXTERN_C void LogIrpShutdownHandler() {
  PAGED_CODE();

  LOG_DEBUG("Flushing... (Max log usage = %08x bytes)",
            g_LogpLogBufferInfo.LogMaximumUsage);
  LOG_INFO("Bye!");
  g_LogpDebugFlag = LOG_PUT_LEVEL_DISABLE;

  // Wait until the log buffer is emptied.
  auto &info = g_LogpLogBufferInfo;
  while (info.LogBufferHead[0]) {
    LogpSleep(LOGP_AUTO_FLUSH_INTERVAL_MSEC);
  }
}

// Terminates the log functions.
ALLOC_TEXT(PAGED, LogTermination)
EXTERN_C void LogTermination(_In_opt_ PDEVICE_OBJECT DeviceObject) {
  PAGED_CODE();

  LOG_DEBUG("Finalizing... (Max log usage = %08x bytes)",
            g_LogpLogBufferInfo.LogMaximumUsage);
  LOG_INFO("Bye!");
  g_LogpDebugFlag = LOG_PUT_LEVEL_DISABLE;
  LogpFinalizeBufferInfo(DeviceObject, &g_LogpLogBufferInfo);
}

// Terminates a log file related code.
ALLOC_TEXT(PAGED, LogpFinalizeBufferInfo)
EXTERN_C static void LogpFinalizeBufferInfo(_In_opt_ PDEVICE_OBJECT
                                                DeviceObject,
                                            _In_ LogBufferInfo *Info) {
  PAGED_CODE();
  NT_ASSERT(Info);

  // Closing the log buffer flush thread.
  if (Info->BufferFlushThreadHandle) {
    Info->BufferFlushThreadShouldBeAlive = false;
    auto status =
        ZwWaitForSingleObject(Info->BufferFlushThreadHandle, FALSE, nullptr);
    if (!NT_SUCCESS(status)) {
      DBG_BREAK();
    }
    ZwClose(Info->BufferFlushThreadHandle);
    Info->BufferFlushThreadHandle = nullptr;
  }

  // Cleaning up other things.
  if (Info->LogFileHandle) {
    ZwClose(Info->LogFileHandle);
    Info->LogFileHandle = nullptr;
  }
  if (Info->LogBuffer2) {
    ExFreePoolWithTag(Info->LogBuffer2, LOGP_POOL_TAG_NAME);
    Info->LogBuffer2 = nullptr;
  }
  if (Info->LogBuffer1) {
    ExFreePoolWithTag(Info->LogBuffer1, LOGP_POOL_TAG_NAME);
    Info->LogBuffer1 = nullptr;
  }

  if (DeviceObject) {
    IoUnregisterShutdownNotification(DeviceObject);
  }
  ExDeleteResourceLite(&Info->Resource);
}

#ifdef _X86_
_Requires_lock_not_held_(*SpinLock) _Acquires_lock_(*SpinLock)
    _IRQL_requires_max_(DISPATCH_LEVEL) _IRQL_saves_
    _IRQL_raises_(DISPATCH_LEVEL) inline KIRQL
    KeAcquireSpinLockRaiseToDpc(_Inout_ PKSPIN_LOCK SpinLock) {
  KIRQL irql = {};
  KeAcquireSpinLock(SpinLock, &irql);
  return irql;
}
#endif

// Actual implementation of logging API.
EXTERN_C NTSTATUS LogpPrint(_In_ ULONG Level, _In_ const char *FunctionName,
                            _In_ const char *Format, ...) {
  auto status = STATUS_SUCCESS;

  if (!LogpIsLogNeeded(Level)) {
    return status;
  }

  va_list args;
  va_start(args, Format);
  char logMessage[300];
  status =
      RtlStringCchVPrintfA(logMessage, RTL_NUMBER_OF(logMessage), Format, args);
  va_end(args);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (logMessage[0] == '\0') {
    return STATUS_INVALID_PARAMETER;
  }

  const auto pureLevel = Level & 0xf0;
  const auto attribute = Level & 0x0f;

  // A single entry of log should not exceed 512 bytes. See
  // Reading and Filtering Debugging Messages in MSDN for details.
  char message[100 + RTL_NUMBER_OF(logMessage)];
  static_assert(RTL_NUMBER_OF(message) <= 512,
                "One log message should not exceed 512 bytes.");
  status = LogpMakePrefix(pureLevel, FunctionName, logMessage, message,
                          RTL_NUMBER_OF(message));
  if (!NT_SUCCESS(status)) {
    return status;
  }

  return LogpPut(message, attribute);
}

// Concatenates meta information such as the current time and a process ID to
// user given log message.
EXTERN_C static NTSTATUS LogpMakePrefix(_In_ ULONG Level,
                                        _In_ const char *FunctionName,
                                        _In_ const char *LogMessage,
                                        _Out_ char *LogBuffer,
                                        _In_ size_t LogBufferLength) {
  char const *levelString = nullptr;
  switch (Level) {
    case LOGP_LEVEL_DEBUG:
      levelString = "DBG";
      break;
    case LOGP_LEVEL_INFO:
      levelString = "INF";
      break;
    case LOGP_LEVEL_WARN:
      levelString = "WRN";
      break;
    case LOGP_LEVEL_ERROR:
      levelString = "ERR";
      break;
    default:
      return STATUS_INVALID_PARAMETER;
  }

  auto status = STATUS_SUCCESS;

  char timeBuffer[20] = {};
  if ((g_LogpDebugFlag & LOG_OPT_DISABLE_TIME) == 0) {
    // Want the current time.
    TIME_FIELDS timeFields;
    LARGE_INTEGER systemTime, localTime;
    KeQuerySystemTime(&systemTime);
    ExSystemTimeToLocalTime(&systemTime, &localTime);
    RtlTimeToTimeFields(&localTime, &timeFields);

    status = RtlStringCchPrintfA(timeBuffer, RTL_NUMBER_OF(timeBuffer),
                                 "%02u:%02u:%02u.%03u\t", timeFields.Hour,
                                 timeFields.Minute, timeFields.Second,
                                 timeFields.Milliseconds);
    if (!NT_SUCCESS(status)) {
      return status;
    }
  }

  char functionNameBuffer[50] = {};
  if ((g_LogpDebugFlag & LOG_OPT_DISABLE_FUNCTION_NAME) == 0) {
    // Want the function name
    const auto baseFunctionName = LogpFindBaseFunctionName(FunctionName);
    status = RtlStringCchPrintfA(functionNameBuffer,
                                 RTL_NUMBER_OF(functionNameBuffer), "%-40s\t",
                                 baseFunctionName);
    if (!NT_SUCCESS(status)) {
      return status;
    }
  }

  //
  // It uses PsGetProcessId(PsGetCurrentProcess()) instead of
  // PsGetCurrentThreadProcessId() because the later sometimes returns
  // unwanted value, for example:
  //  PID == 4 but its image name != ntoskrnl.exe
  // The author is guessing that it is related to attaching processes but
  // not quite sure. The former way works as expected.
  //
  status = RtlStringCchPrintfA(
      LogBuffer, LogBufferLength, "%s%s\t%5lu\t%5lu\t%-15s\t%s%s\r\n",
      timeBuffer, levelString,
      reinterpret_cast<ULONG>(PsGetProcessId(PsGetCurrentProcess())),
      reinterpret_cast<ULONG>(PsGetCurrentThreadId()),
      PsGetProcessImageFileName(PsGetCurrentProcess()), functionNameBuffer,
      LogMessage);
  return status;
}

// Returns the function's base name, for example,
// NamespaceName::ClassName::MethodName will be returned as MethodName.
EXTERN_C static const char *LogpFindBaseFunctionName(
    _In_ const char *FunctionName) {
  if (!FunctionName) {
    return nullptr;
  }

  auto ptr = FunctionName;
  auto name = FunctionName;
  while (*(ptr++)) {
    if (*ptr == ':') {
      name = ptr + 1;
    }
  }
  return name;
}

// Logs the entry according to Attribute and the thread condition.
EXTERN_C static NTSTATUS LogpPut(_In_ const char *Message,
                                 _In_ ULONG Attribute) {
  auto status = STATUS_SUCCESS;

  // Log the entry to a file or buffer.
  auto &info = g_LogpLogBufferInfo;
  if (LogpIsLogFileEnabled(info)) {
    // Can it log it to a file now?
    if (((Attribute & LOGP_LEVEL_OPT_SAFE) == 0) &&
        KeGetCurrentIrql() == PASSIVE_LEVEL && !KeAreAllApcsDisabled()) {
      // Yes, it can. Do it.
      LogpWriteLogBufferToFile(&info);
      status = LogpWriteMessageToFile(Message, info);
    } else {
      // No, it cannot. Buffer it.
      status = LogpBufferMessage(Message, &info);
    }
  }

  // Can it safely be printed?
  if (KeGetCurrentIrql() >= CLOCK_LEVEL) {
    return STATUS_UNSUCCESSFUL;
  }

  DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", Message);
  return status;
}

// Switch the current log buffer and save the contents of old buffer to the log
// file. This function does not flush the log file, so code should call
// LogpWriteMessageToFile() or ZwFlushBuffersFile() later.
EXTERN_C static NTSTATUS LogpWriteLogBufferToFile(
    _In_opt_ LogBufferInfo *Info) {
  NT_ASSERT(Info);
  auto status = STATUS_SUCCESS;

  // Enter a critical section and acquire a reader lock for Info in order to
  // write a log file safely.
  ExEnterCriticalRegionAndAcquireResourceExclusive(&Info->Resource);

  // Acquire a spin lock for Info.LogBuffer(s) in order to switch its head
  // safely.
  const auto irql = KeAcquireSpinLockRaiseToDpc(&Info->SpinLock);
  auto oldLogBuffer = const_cast<char *>(Info->LogBufferHead);
  if (oldLogBuffer[0]) {
    Info->LogBufferHead = (oldLogBuffer == Info->LogBuffer1) ? Info->LogBuffer2
                                                             : Info->LogBuffer1;
    Info->LogBufferHead[0] = '\0';
    Info->LogBufferTail = Info->LogBufferHead;
  }
  KeReleaseSpinLock(&Info->SpinLock, irql);

  // Write all log entries in old log buffer.
  IO_STATUS_BLOCK ioStatus = {};
  for (auto currentLogEntry = oldLogBuffer; currentLogEntry[0]; /**/) {
    const auto currentLogEntryLength = strlen(currentLogEntry);
    status =
        ZwWriteFile(Info->LogFileHandle, nullptr, nullptr, nullptr, &ioStatus,
                    currentLogEntry, static_cast<ULONG>(currentLogEntryLength),
                    nullptr, nullptr);
    if (!NT_SUCCESS(status)) {
      // It could happen when you did not register IRP_SHUTDOWN and call
      // LogIrpShutdownHandler() and the system tried to log to a file after
      // a filesystem was unmounted.
      DBG_BREAK();
    }

    currentLogEntry += currentLogEntryLength + 1;
  }
  oldLogBuffer[0] = '\0';

  ExReleaseResourceAndLeaveCriticalRegion(&Info->Resource);
  return status;
}

// Logs the current log entry to and flush the log file.
EXTERN_C static NTSTATUS LogpWriteMessageToFile(
    _In_ const char *Message, _In_ const LogBufferInfo &Info) {
  IO_STATUS_BLOCK ioStatus = {};
  auto status =
      ZwWriteFile(Info.LogFileHandle, nullptr, nullptr, nullptr, &ioStatus,
                  const_cast<char *>(Message),
                  static_cast<ULONG>(strlen(Message)), nullptr, nullptr);
  if (!NT_SUCCESS(status)) {
    // It could happen when you did not register IRP_SHUTDOWN and call
    // LogIrpShutdownHandler() and the system tried to log to a file after
    // a filesystem was unmounted.
    DBG_BREAK();
  }
  status = ZwFlushBuffersFile(Info.LogFileHandle, &ioStatus);
  return status;
}

// Buffer the log entry to the log buffer.
EXTERN_C static NTSTATUS LogpBufferMessage(_In_ const char *Message,
                                           _In_opt_ LogBufferInfo *Info) {
  NT_ASSERT(Info);

  // Acquire a spin lock to add the log safely.
  const auto irql = KeAcquireSpinLockRaiseToDpc(&Info->SpinLock);

  // Copy the current log to the buffer.
  size_t usedBufferSize = Info->LogBufferTail - Info->LogBufferHead;
  auto status =
      RtlStringCchCopyA(const_cast<char *>(Info->LogBufferTail),
                        LOGP_BUFFER_USABLE_SIZE - usedBufferSize, Message);

  // Update Info.LogMaximumUsage if necessary.
  if (NT_SUCCESS(status)) {
    const auto messageLength = strlen(Message) + 1;
    Info->LogBufferTail += messageLength;
    usedBufferSize += messageLength;
    if (usedBufferSize > Info->LogMaximumUsage) {
      Info->LogMaximumUsage = usedBufferSize;  // Update
    }
  } else {
    Info->LogMaximumUsage = LOGP_BUFFER_SIZE;  // Indicates overflow
  }
  *Info->LogBufferTail = '\0';

  KeReleaseSpinLock(&Info->SpinLock, irql);
  return status;
}

// Returns true when a log file is enabled.
EXTERN_C static bool LogpIsLogFileEnabled(_In_ const LogBufferInfo &Info) {
  if (Info.LogFileHandle) {
    NT_ASSERT(Info.LogBuffer1);
    NT_ASSERT(Info.LogBuffer2);
    NT_ASSERT(Info.LogBufferHead);
    NT_ASSERT(Info.LogBufferTail);
    return true;
  }
  NT_ASSERT(!Info.LogBuffer1);
  NT_ASSERT(!Info.LogBuffer2);
  NT_ASSERT(!Info.LogBufferHead);
  NT_ASSERT(!Info.LogBufferTail);
  return false;
}

// Returns true when logging is necessary according to the log's severity and
// a set log level.
EXTERN_C static bool LogpIsLogNeeded(_In_ ULONG Level) {
  return !!(g_LogpDebugFlag & Level);
}

// A thread runs as long as info.BufferFlushThreadShouldBeAlive is true and
// flushes a log buffer to a log file every LOGP_AUTO_FLUSH_INTERVAL_MSEC msec.
ALLOC_TEXT(PAGED, LogpBufferFlushThreadRoutine)
EXTERN_C static VOID LogpBufferFlushThreadRoutine(_In_ void *StartContext) {
  PAGED_CODE();
  auto status = STATUS_SUCCESS;
  auto info = reinterpret_cast<LogBufferInfo *>(StartContext);
  LOG_DEBUG("Log thread started.");
  NT_ASSERT(LogpIsLogFileEnabled(*info));

  while (info->BufferFlushThreadShouldBeAlive) {
    if (info->LogBufferHead[0]) {
      NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
      NT_ASSERT(!KeAreAllApcsDisabled());
      status = LogpWriteLogBufferToFile(info);
      // Do not flush the file for overall performance. Even a case of
      // bug check, we should be able to recover logs by looking at both
      // log buffers.
    }
    LogpSleep(LOGP_AUTO_FLUSH_INTERVAL_MSEC);
  }
  LOG_DEBUG("Log thread is ending.");
  PsTerminateSystemThread(status);
}

// Sleep the current thread's execution for Millisecond milli-seconds.
ALLOC_TEXT(PAGED, LogpSleep)
EXTERN_C static NTSTATUS LogpSleep(_In_ LONG Millisecond) {
  PAGED_CODE();

  LARGE_INTEGER interval = {};
  interval.QuadPart = -(10000 * Millisecond);  // msec
  return KeDelayExecutionThread(KernelMode, FALSE, &interval);
}
