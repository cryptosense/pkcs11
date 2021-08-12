#include "prelude.h"

/* Define mutexes */

// Windows
#ifdef WIN32
// extracted from https://github.com/ANSSI-FR/caml-crush/blob/master/src/client-lib/modwrap.c
typedef CRITICAL_SECTION pthread_mutex_t;

void pthread_mutex_init(LPCRITICAL_SECTION mymutex, void *useless){
  InitializeCriticalSection(mymutex);
  return;
}
void pthread_mutex_lock(LPCRITICAL_SECTION mymutex){
  EnterCriticalSection(mymutex);
  return;
}
void pthread_mutex_unlock(LPCRITICAL_SECTION mymutex){
  LeaveCriticalSection(mymutex);
  return;
}
#endif

static pthread_mutex_t mutex;

// prototype of the C_GetFunctionList function to initialize the
// function_list structure below.
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

// Global structure of function list. All fields beside
// C_GetFunctionList must have been defined before including this
// file.
CK_FUNCTION_LIST function_list = {
  {2, 20},
  C_Initialize,
  C_Finalize,
  C_GetInfo,
  C_GetFunctionList,
  C_GetSlotList,
  C_GetSlotInfo,
  C_GetTokenInfo,
  C_GetMechanismList,
  C_GetMechanismInfo,
  C_InitToken,
  C_InitPIN,
  C_SetPIN,
  C_OpenSession,
  C_CloseSession,
  C_CloseAllSessions,
  C_GetSessionInfo,
  C_GetOperationState,
  C_SetOperationState,
  C_Login,
  C_Logout,
  C_CreateObject,
  C_CopyObject,
  C_DestroyObject,
  C_GetObjectSize,
  C_GetAttributeValue,
  C_SetAttributeValue,
  C_FindObjectsInit,
  C_FindObjects,
  C_FindObjectsFinal,
  C_EncryptInit,
  C_Encrypt,
  C_EncryptUpdate,
  C_EncryptFinal,
  C_DecryptInit,
  C_Decrypt,
  C_DecryptUpdate,
  C_DecryptFinal,
  C_DigestInit,
  C_Digest,
  C_DigestUpdate,
  C_DigestKey,
  C_DigestFinal,
  C_SignInit,
  C_Sign,
  C_SignUpdate,
  C_SignFinal,
  C_SignRecoverInit,
  C_SignRecover,
  C_VerifyInit,
  C_Verify,
  C_VerifyUpdate,
  C_VerifyFinal,
  C_VerifyRecoverInit,
  C_VerifyRecover,
  C_DigestEncryptUpdate,
  C_DecryptDigestUpdate,
  C_SignEncryptUpdate,
  C_DecryptVerifyUpdate,
  C_GenerateKey,
  C_GenerateKeyPair,
  C_WrapKey,
  C_UnwrapKey,
  C_DeriveKey,
  C_SeedRandom,
  C_GenerateRandom,
  C_GetFunctionStatus,
  C_CancelFunction,
  C_WaitForSlotEvent
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
  if (ppFunctionList == NULL) return CKR_ARGUMENTS_BAD;
  *ppFunctionList = &function_list;
  return CKR_OK;
}

/* Locking functions
 * Each UC_XXX function is wrapped using the following scheme:
 *
 *    C_XXX (args) {
 *            pthread_mutex_lock(&mutex);
 *            rv = UC_XXX(args);
 *            pthread_mutex_unlock(&mutex);
 *            return rv;
 *    }
 *
 */

#define W1(name, t1) \
extern CK_RV U##name(t1); \
unsigned long name(t1 x1) \
{ \
	pthread_mutex_lock(&mutex); \
	unsigned long rv = U##name(x1); \
	pthread_mutex_unlock(&mutex); \
	return rv; \
}

#define W2(name, t1, t2) \
extern CK_RV U##name(t1, t2); \
unsigned long name(t1 x1, t2 x2) \
{ \
	pthread_mutex_lock(&mutex); \
	unsigned long rv = U##name(x1, x2); \
	pthread_mutex_unlock(&mutex); \
	return rv; \
}

#define W3(name, t1, t2, t3) \
extern CK_RV U##name(t1, t2, t3); \
unsigned long name(t1 x1, t2 x2, t3 x3) \
{ \
	pthread_mutex_lock(&mutex); \
	unsigned long rv = U##name(x1, x2, x3); \
	pthread_mutex_unlock(&mutex); \
	return rv; \
}

#define W4(name, t1, t2, t3, t4) \
extern CK_RV U##name(t1, t2, t3, t4); \
unsigned long name(t1 x1, t2 x2, t3 x3, t4 x4) \
{ \
	pthread_mutex_lock(&mutex); \
	unsigned long rv = U##name(x1, x2, x3, x4); \
	pthread_mutex_unlock(&mutex); \
	return rv; \
}

#define W5(name, t1, t2, t3, t4, t5) \
extern CK_RV U##name(t1, t2, t3, t4, t5); \
unsigned long name(t1 x1, t2 x2, t3 x3, t4 x4, t5 x5) \
{ \
	pthread_mutex_lock(&mutex); \
	unsigned long rv = U##name(x1, x2, x3, x4, x5); \
	pthread_mutex_unlock(&mutex); \
	return rv; \
}

#define W6(name, t1, t2, t3, t4, t5, t6) \
extern CK_RV U##name(t1, t2, t3, t4, t5, t6); \
unsigned long name(t1 x1, t2 x2, t3 x3, t4 x4, t5 x5, t6 x6) \
{ \
	pthread_mutex_lock(&mutex); \
	unsigned long rv = U##name(x1, x2, x3, x4, x5, x6); \
	pthread_mutex_unlock(&mutex); \
	return rv; \
}

#define W8(name, t1, t2, t3, t4, t5, t6, t7, t8) \
extern CK_RV U##name(t1, t2, t3, t4, t5, t6, t7, t8); \
unsigned long name(t1 x1, t2 x2, t3 x3, t4 x4, t5 x5, t6 x6, t7 x7, t8 x8) \
{ \
	pthread_mutex_lock(&mutex); \
	unsigned long rv = U##name(x1, x2, x3, x4, x5, x6, x7, x8); \
	pthread_mutex_unlock(&mutex); \
	return rv; \
}

W1(C_Initialize, void*)
W1(C_Finalize, void*)
W1(C_GetInfo, struct CK_INFO*)
W2(C_GetTokenInfo, unsigned long, struct CK_TOKEN_INFO*)
W3(C_GetSlotList, unsigned char, unsigned long*, unsigned long*)
W2(C_GetSlotInfo, unsigned long, struct CK_SLOT_INFO*)
W3(C_GetMechanismList, unsigned long, unsigned long*, unsigned long*)
W3(C_GetMechanismInfo, unsigned long, unsigned long, struct CK_MECHANISM_INFO*)
W4(C_InitToken, unsigned long, unsigned char*, unsigned long, unsigned char*)
W3(C_InitPIN, unsigned long, unsigned char*, unsigned long)
W5(C_SetPIN, unsigned long, unsigned char*, unsigned long, unsigned char*, unsigned long)
W5(C_OpenSession, unsigned long, unsigned long, void*, CK_NOTIFY, unsigned long*)
W1(C_CloseSession, unsigned long)
W1(C_CloseAllSessions, unsigned long)
W2(C_GetSessionInfo, unsigned long, struct CK_SESSION_INFO*)
W3(C_GetOperationState, unsigned long, unsigned char*, unsigned long*)
W5(C_SetOperationState, unsigned long, unsigned char*, unsigned long, unsigned long, unsigned long)
W4(C_Login, unsigned long, unsigned long, unsigned char*, unsigned long)
W1(C_Logout, unsigned long)
W4(C_CreateObject, unsigned long, struct CK_ATTRIBUTE*, unsigned long, unsigned long*)
W5(C_CopyObject, unsigned long, unsigned long, struct CK_ATTRIBUTE*, unsigned long, unsigned long*)
W2(C_DestroyObject, unsigned long, unsigned long)
W3(C_GetObjectSize, unsigned long, unsigned long, unsigned long*)
W4(C_GetAttributeValue, unsigned long, unsigned long, struct CK_ATTRIBUTE*, unsigned long)
W4(C_SetAttributeValue, unsigned long, unsigned long, struct CK_ATTRIBUTE*, unsigned long)
W3(C_FindObjectsInit, unsigned long, struct CK_ATTRIBUTE*, unsigned long)
W4(C_FindObjects, unsigned long, unsigned long*, unsigned long, unsigned long*)
W1(C_FindObjectsFinal, unsigned long)
W3(C_EncryptInit, unsigned long, struct CK_MECHANISM*, unsigned long)
W5(C_Encrypt, unsigned long, unsigned char*, unsigned long, unsigned char*, unsigned long*)
W5(C_EncryptUpdate, unsigned long, unsigned char*, unsigned long, unsigned char*, unsigned long*)
W3(C_EncryptFinal, unsigned long, unsigned char*, unsigned long*)
W3(C_DecryptInit, unsigned long, struct CK_MECHANISM*, unsigned long)
W5(C_Decrypt, unsigned long, unsigned char*, unsigned long, unsigned char*, unsigned long*)
W5(C_DecryptUpdate, unsigned long, unsigned char*, unsigned long, unsigned char*, unsigned long*)
W3(C_DecryptFinal, unsigned long, unsigned char*, unsigned long*)
W2(C_DigestInit, unsigned long, struct CK_MECHANISM*)
W5(C_Digest, unsigned long, unsigned char*, unsigned long, unsigned char*, unsigned long*)
W3(C_DigestUpdate, unsigned long, unsigned char*, unsigned long)
W2(C_DigestKey, unsigned long, unsigned long)
W3(C_DigestFinal, unsigned long, unsigned char*, unsigned long*)
W3(C_SignInit, unsigned long, struct CK_MECHANISM*, unsigned long)
W5(C_Sign, unsigned long, unsigned char*, unsigned long, unsigned char*, unsigned long*)
W3(C_SignUpdate, unsigned long, unsigned char*, unsigned long)
W3(C_SignFinal, unsigned long, unsigned char*, unsigned long*)
W3(C_SignRecoverInit, unsigned long, struct CK_MECHANISM*, unsigned long)
W5(C_SignRecover, unsigned long, unsigned char*, unsigned long, unsigned char*, unsigned long*)
W3(C_VerifyInit, unsigned long, struct CK_MECHANISM*, unsigned long)
W5(C_Verify, unsigned long, unsigned char*, unsigned long, unsigned char*, unsigned long)
W3(C_VerifyUpdate, unsigned long, unsigned char*, unsigned long)
W3(C_VerifyFinal, unsigned long, unsigned char*, unsigned long)
W3(C_VerifyRecoverInit, unsigned long, struct CK_MECHANISM*, unsigned long)
W5(C_VerifyRecover, unsigned long, unsigned char*, unsigned long, unsigned char*, unsigned long*)
W5(C_DigestEncryptUpdate, unsigned long, unsigned char*, unsigned long, unsigned char*, unsigned long*)
W5(C_DecryptDigestUpdate, unsigned long, unsigned char*, unsigned long, unsigned char*, unsigned long*)
W5(C_SignEncryptUpdate, unsigned long, unsigned char*, unsigned long, unsigned char*, unsigned long*)
W5(C_DecryptVerifyUpdate, unsigned long, unsigned char*, unsigned long, unsigned char*, unsigned long*)
W5(C_GenerateKey, unsigned long, struct CK_MECHANISM*, struct CK_ATTRIBUTE*, unsigned long, unsigned long*)
W8(C_GenerateKeyPair, unsigned long, struct CK_MECHANISM*, struct CK_ATTRIBUTE*, unsigned long, struct CK_ATTRIBUTE*, unsigned long, unsigned long*, unsigned long*)
W6(C_WrapKey, unsigned long, struct CK_MECHANISM*, unsigned long, unsigned long, unsigned char*, unsigned long*)
W8(C_UnwrapKey, unsigned long, struct CK_MECHANISM*, unsigned long, unsigned char*, unsigned long, struct CK_ATTRIBUTE*, unsigned long, unsigned long*)
W6(C_DeriveKey, unsigned long, struct CK_MECHANISM*, unsigned long, struct CK_ATTRIBUTE*, unsigned long, unsigned long*)
W3(C_SeedRandom, unsigned long, unsigned char*, unsigned long)
W3(C_GenerateRandom, unsigned long, unsigned char*, unsigned long)
W1(C_GetFunctionStatus, unsigned long)
W1(C_CancelFunction, unsigned long)
W3(C_WaitForSlotEvent, unsigned long, unsigned long*, void*)

/* We need to initialize the dll properly. */

/* Initialize the OCaml runtime. */
static void initialize_ocaml_runtime(){
  char *caml_argv[1] = { NULL };
  caml_startup(caml_argv);
}

/* Finalize the OCaml runtime and run at_exit. */
static void finalize_ocaml_runtime(){
  value * at_exit = caml_named_value("Stdlib.do_at_exit");
  if (at_exit != NULL) caml_callback_exn(*at_exit, Val_unit);
}

/* Expose to the OCaml code a way to retrieve the location of the
   (OCaml) dll. */
char * caml_dll_path = NULL;

CAMLprim value caml_get_dll_path(value unit){
  CAMLparam0 ();   /* unit is unused */
  if(caml_dll_path == NULL) caml_raise_not_found();
  CAMLreturn(caml_copy_string(caml_dll_path));
}

static char* xstrdup(const char* src){
	char* result;
#ifdef __GLIBC__
	result = strdup(src);
	if (result == NULL) {
		perror("strdup");
		exit(1);
	}
#else
	int len = strlen(src);
	result = malloc(len + 1);
	if (result == NULL) {
		perror("malloc");
		exit(1);
	}
	strcpy(result, src);
#endif
	return result;
}

#ifdef _AIX
/*
 * On AIX, it is necessary to dereference function pointers
 * to get the real address.
 * See https://stackoverflow.com/a/10050746
 */
static void *deref_pointer_glue(void *orig)
{
	void **ptr = (void **) orig;
	return *ptr;
}

typedef struct {
	char* dli_fname;
} Dl_info;

int dladdr(void* s, Dl_info* i)
{
	size_t bufSize = 40960;
	struct ld_info* ldi;
	int r;
	s = deref_pointer_glue(s);
	void *buf = (void *)malloc(bufSize);
	if (!buf) {
		i->dli_fname = NULL;
		return 0;
	}
	r = loadquery(L_GETINFO, buf, (int)bufSize);
	if (r == -1) {
		i->dli_fname = NULL;
		return 0;
	}
	do {
		ldi = (struct ld_info*)buf;
		void *textorg = ldi->ldinfo_textorg;
		unsigned int size = ldi->ldinfo_textsize;
		if ((textorg <= s) && (s < (textorg + size))) {
			i->dli_fname = ldi->ldinfo_filename;
			return 1;
		}
		buf += ldi->ldinfo_next;
	} while (ldi->ldinfo_next);
	i->dli_fname = NULL;
	return 0;
}
#endif

#ifdef WIN32
/* Main initialization function for windows. We do not perform any
   update when a new thread is attached to the dll.
  */
BOOL WINAPI DllMain(
_In_ HINSTANCE hinstDLL,
_In_ DWORD fdwReason,
_In_ LPVOID lpvReserved
)
{
  TCHAR buffer[MAX_PATH];
  switch (fdwReason)
  {
    case DLL_PROCESS_ATTACH:
      GetModuleFileName(hinstDLL, buffer, MAX_PATH);
      caml_dll_path = xstrdup(buffer);
      pthread_mutex_init(&mutex, NULL);
      initialize_ocaml_runtime();
      break;
    case DLL_THREAD_ATTACH:
      break;
    case DLL_PROCESS_DETACH:
      finalize_ocaml_runtime();
      free(caml_dll_path);
      break;
    case DLL_THREAD_DETACH:
      break;
  }
  return TRUE;
}
#endif


#ifndef WIN32

__attribute__((constructor))
static void initialize_dll(){
  Dl_info dl_info;

  /* Initialize the global library mutex. */
  pthread_mutex_init(&mutex, NULL);

  /* Resolves the name and file where the address symbol is
     located. This is useful to provide the name of the dll to the
     calling library.  */
  dladdr((void *)initialize_ocaml_runtime, &dl_info);
  caml_dll_path = xstrdup(dl_info.dli_fname);
  initialize_ocaml_runtime();
}
#endif

#ifndef WIN32
__attribute__((destructor))
static void finalize_dll(){
  finalize_ocaml_runtime();
  free(caml_dll_path);
}
#endif
