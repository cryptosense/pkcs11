#ifdef _WIN32

#include <windows.h>
#include <conio.h>
#define DLOPEN(lib) LoadLibrary(lib)
#define DLSYM(h, function) GetProcAddress(h, function)
#define DLCLOSE(h) FreeLibrary(h)

#pragma pack(push, cryptoki, 1)
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType __declspec(dllexport) name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#include "pkcs11.h"
#pragma pack(pop, cryptoki)

#else // LINUX

#include <dlfcn.h>
#define DLOPEN(lib) dlopen(lib, RTLD_NOW)
#define DLSYM(h, function) dlsym(h, function)
#define DLCLOSE(h) dlclose(h)
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#include "pkcs11.h"

#endif

// We only need to import pkcs11t.h to get the data types.
/* /\* #include "pkcs11t.h" *\/ */

#ifndef NULL_PTR
#define NULL_PTR NULL
#endif

#define OK_OR_FAIL(rv) do {if (rv != CKR_OK) { printf("%s line %d: CKR %x\n", __FILE__, __LINE__,rv); return rv;}} while (0)


/* Define the type of the functions that are exported by this
   module. By convention, we prefix the name of all the functions
   with "M". */

#ifdef CK_DECLARE_FUNCTION
#undef CK_DECLARE_FUNCTION
#endif

#define CK_DECLARE_FUNCTION(returning, name) returning name
#define CK_NEED_ARG_LIST 1
#define CK_PKCS11_FUNCTION_INFO(name) CK_DECLARE_FUNCTION(CK_RV, M##name)
#include "pkcs11f.h"
#undef CK_NEED_ARG_LIST

CK_RV MC_LoadModule(char * driver);
CK_RV MC_UnloadModule(void);
