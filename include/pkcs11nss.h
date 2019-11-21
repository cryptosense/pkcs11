/* This file includes extra definitions required to use the NSS library that
 * are not in the PKCS#11 standard includes. */

/* CK_NSS_C_INITIALIZE_ARGS provides the optional arguments to
 * the modified C_Initialize used by NSS */
 typedef struct CK_NSS_C_INITIALIZE_ARGS {
  CK_CREATEMUTEX CreateMutex;
  CK_DESTROYMUTEX DestroyMutex;
  CK_LOCKMUTEX LockMutex;
  CK_UNLOCKMUTEX UnlockMutex;
  CK_FLAGS flags;
  CK_VOID_PTR LibraryParameters;
  CK_VOID_PTR pReserved;
} CK_NSS_C_INITIALIZE_ARGS;

typedef CK_NSS_C_INITIALIZE_ARGS CK_PTR CK_NSS_C_INITIALIZE_ARGS_PTR;
