#define _GNU_SOURCE
#include <stdio.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/callback.h>
#include <caml/alloc.h>

#ifdef WIN32
// Windows
#include <windows.h>
#else

#if defined(__GLIBC__) || (defined(__sun) && defined(__SVR4))
#include <dlfcn.h>
#endif
#ifdef _AIX
#include <sys/ldr.h>
#endif

#include <pthread.h>
#include <string.h>
#endif

/* Macros needed by PKCS#11 headers */
#ifndef NULL_PTR
#define NULL_PTR NULL
#endif

#ifdef WIN32
// Windows
#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType __declspec(dllexport) name
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#include "pkcs11.h"
#pragma pack(pop, cryptoki)
// Linux
#else
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#include "pkcs11.h"
#endif
