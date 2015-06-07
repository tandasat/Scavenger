// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

extern "C" {
#pragma warning(push, 0)
#include <fltKernel.h>
#include <Wdmsec.h>
#include <windef.h>
#include <ntimage.h>
#include <stdarg.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <intrin.h>
#include <Aux_klib.h>
#include <bcrypt.h>
#pragma warning(pop)
}

#ifndef _HAS_EXCEPTIONS
#define _HAS_EXCEPTIONS 0
#endif
#include "../Common/ScopedResource/unique_resource.h"
#include "../Common/ScopedResource/scope_exit.h"

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

// Specifies where the code should be located
#ifdef ALLOC_PRAGMA
#define ALLOC_TEXT(Section, Name) __pragma(alloc_text(Section, Name))
#else
#define ALLOC_TEXT(Section, Name)
#endif

// Break point that works only when a debugger is enabled
#ifndef DBG_BREAK
#ifdef _ARM_
// Nullify it since an ARM device never allow us to attach a debugger.
#define DBG_BREAK()
#else  // _ARM_
#define DBG_BREAK()          \
  if (KD_DEBUGGER_ENABLED) { \
    __debugbreak();          \
  } else {                   \
  }                          \
  reinterpret_cast<void *>(0)
#endif  // _ARM_
#endif  // DBG_BREAK

// To explicitly suppress warnings
#ifndef UNREFERENCED_LOCAL_VARIABLE
#define UNREFERENCED_LOCAL_VARIABLE(x) (reinterpret_cast<void *>(!(x)))
#endif

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

static const ULONG SCVN_POOL_TAG_NAME = 'nvcs';

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//
