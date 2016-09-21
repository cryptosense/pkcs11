/* Module management for PKCS11 tokens. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "pkcs11_module.h"

/*  Check that the module is loaded and that the function is available. */
#define CHECK_FUNCTION(function) do {\
  if(pkcs11_functions == NULL) {return CKR_GENERAL_ERROR;}; \
  if(pkcs11_functions->function == NULL) {return CKR_FUNCTION_NOT_SUPPORTED;}\
  } while (0);

#define FUNCTION_CALL(function) pkcs11_functions->function


// Global variables
void *pkcs11_module_handle = NULL;
CK_FUNCTION_LIST *pkcs11_functions = NULL;

CK_RV
MC_LoadModule (char *driver)
{
  CK_RV rv = CKR_OK;
  CK_RV (*get_function_list) (CK_FUNCTION_LIST_PTR_PTR);

  pkcs11_module_handle = DLOPEN (driver);

  if (pkcs11_module_handle == NULL)
    {
      // TODO: could try with RTLD_LAZY
      return CKR_FUNCTION_FAILED;
    };

  *(void **) (&get_function_list) =
    (CK_C_GetFunctionList) (DLSYM
			    (pkcs11_module_handle, "C_GetFunctionList"));

  if (get_function_list == NULL)
    {
      return CKR_FUNCTION_FAILED;
    };

  rv = get_function_list (&pkcs11_functions);

  return rv;
}

CK_RV
MC_UnloadModule (void)
{
  if (pkcs11_module_handle == NULL)
    {
      return CKR_FUNCTION_FAILED;
    };

  DLCLOSE (pkcs11_module_handle);

  return CKR_OK;
}

			/********************/
                        /* PKCS11 Functions */
			/********************/
CK_RV MC_Initialize (CK_VOID_PTR pInitArgs)
{
  CHECK_FUNCTION (C_Initialize);
  return (FUNCTION_CALL (C_Initialize) (pInitArgs));
};

CK_RV MC_Finalize (CK_VOID_PTR pReserved)
{
  CHECK_FUNCTION (C_Finalize);
  return (FUNCTION_CALL (C_Finalize) (pReserved));
};

CK_RV
MC_GetInfo (CK_INFO_PTR pInfo)
{
  CHECK_FUNCTION (C_GetInfo);
  return (FUNCTION_CALL (C_GetInfo) (pInfo));
};

CK_RV MC_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
  CHECK_FUNCTION (C_GetFunctionList);
  return (FUNCTION_CALL (C_GetFunctionList) (ppFunctionList));
};

CK_RV MC_GetSlotList
  (CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
  CHECK_FUNCTION (C_GetSlotList);
  return (FUNCTION_CALL (C_GetSlotList) (tokenPresent, pSlotList, pulCount));
};

CK_RV MC_GetSlotInfo (CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
  CHECK_FUNCTION (C_GetSlotInfo);
  return (FUNCTION_CALL (C_GetSlotInfo) (slotID, pInfo));
};

CK_RV MC_GetTokenInfo (CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
  CHECK_FUNCTION (C_GetTokenInfo);
  return (FUNCTION_CALL (C_GetTokenInfo) (slotID, pInfo));
};

CK_RV MC_GetMechanismList
  (CK_SLOT_ID slotID,
   CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
  CHECK_FUNCTION (C_GetMechanismList);
  return (FUNCTION_CALL (C_GetMechanismList)
	  (slotID, pMechanismList, pulCount));
};

CK_RV MC_GetMechanismInfo
  (CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
  CHECK_FUNCTION (C_GetMechanismInfo);
  return (FUNCTION_CALL (C_GetMechanismInfo) (slotID, type, pInfo));
};

CK_RV MC_InitToken
  (CK_SLOT_ID slotID,
   CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
  CHECK_FUNCTION (C_InitToken);
  return (FUNCTION_CALL (C_InitToken) (slotID, pPin, ulPinLen, pLabel));
};

CK_RV MC_InitPIN
  (CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
  CHECK_FUNCTION (C_InitPIN);
  return (FUNCTION_CALL (C_InitPIN) (hSession, pPin, ulPinLen));
};

CK_RV MC_SetPIN
  (CK_SESSION_HANDLE hSession,
   CK_UTF8CHAR_PTR pOldPin,
   CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
  CHECK_FUNCTION (C_SetPIN);
  return (FUNCTION_CALL (C_SetPIN) (hSession,
				    pOldPin, ulOldLen, pNewPin, ulNewLen));
};

CK_RV MC_OpenSession
  (CK_SLOT_ID slotID,
   CK_FLAGS flags,
   CK_VOID_PTR pApplication,
   CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
  CHECK_FUNCTION (C_OpenSession);
  return (FUNCTION_CALL (C_OpenSession) (slotID,
					 flags,
					 pApplication, Notify, phSession));
};

CK_RV MC_CloseSession (CK_SESSION_HANDLE hSession)
{
  CHECK_FUNCTION (C_CloseSession);
  return (FUNCTION_CALL (C_CloseSession) (hSession));
};

CK_RV MC_CloseAllSessions (CK_SLOT_ID slotID)
{
  CHECK_FUNCTION (C_CloseAllSessions);
  return (FUNCTION_CALL (C_CloseAllSessions) (slotID));
};

CK_RV MC_GetSessionInfo
  (CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
  CHECK_FUNCTION (C_GetSessionInfo);
  return (FUNCTION_CALL (C_GetSessionInfo) (hSession, pInfo));
};

CK_RV MC_GetOperationState
  (CK_SESSION_HANDLE hSession,
   CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
  CHECK_FUNCTION (C_GetOperationState);
  return (FUNCTION_CALL (C_GetOperationState) (hSession,
					       pOperationState,
					       pulOperationStateLen));
};

CK_RV MC_SetOperationState
  (CK_SESSION_HANDLE hSession,
   CK_BYTE_PTR pOperationState,
   CK_ULONG ulOperationStateLen,
   CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
  CHECK_FUNCTION (C_SetOperationState);
  return (FUNCTION_CALL (C_SetOperationState) (hSession,
					       pOperationState,
					       ulOperationStateLen,
					       hEncryptionKey,
					       hAuthenticationKey));
};

CK_RV MC_Login
  (CK_SESSION_HANDLE hSession,
   CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
  CHECK_FUNCTION (C_Login);
  return (FUNCTION_CALL (C_Login) (hSession, userType, pPin, ulPinLen));
};

CK_RV MC_Logout (CK_SESSION_HANDLE hSession)
{
  CHECK_FUNCTION (C_Logout);
  return (FUNCTION_CALL (C_Logout) (hSession));
};

CK_RV MC_CreateObject
  (CK_SESSION_HANDLE hSession,
   CK_ATTRIBUTE_PTR pTemplate,
   CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
  CHECK_FUNCTION (C_CreateObject);
  return (FUNCTION_CALL (C_CreateObject) (hSession,
					  pTemplate, ulCount, phObject));
};

CK_RV MC_CopyObject
  (CK_SESSION_HANDLE hSession,
   CK_OBJECT_HANDLE hObject,
   CK_ATTRIBUTE_PTR pTemplate,
   CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
  CHECK_FUNCTION (C_CopyObject);
  return (FUNCTION_CALL (C_CopyObject) (hSession,
					hObject,
					pTemplate, ulCount, phNewObject));
};

CK_RV MC_DestroyObject (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
  CHECK_FUNCTION (C_DestroyObject);
  return (FUNCTION_CALL (C_DestroyObject) (hSession, hObject));
};

CK_RV MC_GetObjectSize
  (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
  CHECK_FUNCTION (C_GetObjectSize);
  return (FUNCTION_CALL (C_GetObjectSize) (hSession, hObject, pulSize));
};

CK_RV MC_GetAttributeValue
  (CK_SESSION_HANDLE hSession,
   CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
  CHECK_FUNCTION (C_GetAttributeValue);
  return (FUNCTION_CALL (C_GetAttributeValue) (hSession,
					       hObject, pTemplate, ulCount));
};

CK_RV MC_SetAttributeValue
  (CK_SESSION_HANDLE hSession,
   CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
  CHECK_FUNCTION (C_SetAttributeValue);
  return (FUNCTION_CALL (C_SetAttributeValue) (hSession,
					       hObject, pTemplate, ulCount));
};

CK_RV MC_FindObjectsInit
  (CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
  CHECK_FUNCTION (C_FindObjectsInit);
  return (FUNCTION_CALL (C_FindObjectsInit) (hSession, pTemplate, ulCount));
};

CK_RV MC_FindObjects
  (CK_SESSION_HANDLE hSession,
   CK_OBJECT_HANDLE_PTR phObject,
   CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
  CHECK_FUNCTION (C_FindObjects);
  return (FUNCTION_CALL (C_FindObjects) (hSession,
					 phObject,
					 ulMaxObjectCount, pulObjectCount));
};

CK_RV MC_FindObjectsFinal (CK_SESSION_HANDLE hSession)
{
  CHECK_FUNCTION (C_FindObjectsFinal);
  return (FUNCTION_CALL (C_FindObjectsFinal) (hSession));
};

CK_RV MC_EncryptInit
  (CK_SESSION_HANDLE hSession,
   CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
  CHECK_FUNCTION (C_EncryptInit);
  return (FUNCTION_CALL (C_EncryptInit) (hSession, pMechanism, hKey));
};

CK_RV MC_Encrypt
  (CK_SESSION_HANDLE hSession,
   CK_BYTE_PTR pData,
   CK_ULONG ulDataLen,
   CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
  CHECK_FUNCTION (C_Encrypt);
  return (FUNCTION_CALL (C_Encrypt) (hSession,
				     pData,
				     ulDataLen,
				     pEncryptedData, pulEncryptedDataLen));
};

CK_RV MC_EncryptUpdate
  (CK_SESSION_HANDLE hSession,
   CK_BYTE_PTR pPart,
   CK_ULONG ulPartLen,
   CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
  CHECK_FUNCTION (C_EncryptUpdate);
  return (FUNCTION_CALL (C_EncryptUpdate) (hSession,
					   pPart,
					   ulPartLen,
					   pEncryptedPart,
					   pulEncryptedPartLen));
};

CK_RV MC_EncryptFinal
  (CK_SESSION_HANDLE hSession,
   CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
  CHECK_FUNCTION (C_EncryptFinal);
  return (FUNCTION_CALL (C_EncryptFinal) (hSession,
					  pLastEncryptedPart,
					  pulLastEncryptedPartLen));
};

CK_RV MC_DecryptInit
  (CK_SESSION_HANDLE hSession,
   CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
  CHECK_FUNCTION (C_DecryptInit);
  return (FUNCTION_CALL (C_DecryptInit) (hSession, pMechanism, hKey));
};

CK_RV MC_Decrypt
  (CK_SESSION_HANDLE hSession,
   CK_BYTE_PTR pEncryptedData,
   CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
  CHECK_FUNCTION (C_Decrypt);
  return (FUNCTION_CALL (C_Decrypt) (hSession,
				     pEncryptedData,
				     ulEncryptedDataLen, pData, pulDataLen));
};

CK_RV MC_DecryptUpdate
  (CK_SESSION_HANDLE hSession,
   CK_BYTE_PTR pEncryptedPart,
   CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
  CHECK_FUNCTION (C_DecryptUpdate);
  return (FUNCTION_CALL (C_DecryptUpdate) (hSession,
					   pEncryptedPart,
					   ulEncryptedPartLen,
					   pPart, pulPartLen));
};

CK_RV MC_DecryptFinal
  (CK_SESSION_HANDLE hSession,
   CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
  CHECK_FUNCTION (C_DecryptFinal);
  return (FUNCTION_CALL (C_DecryptFinal) (hSession,
					  pLastPart, pulLastPartLen));
};

CK_RV MC_DigestInit (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
  CHECK_FUNCTION (C_DigestInit);
  return (FUNCTION_CALL (C_DigestInit) (hSession, pMechanism));
};

CK_RV MC_Digest
  (CK_SESSION_HANDLE hSession,
   CK_BYTE_PTR pData,
   CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
  CHECK_FUNCTION (C_Digest);
  return (FUNCTION_CALL (C_Digest) (hSession,
				    pData, ulDataLen, pDigest, pulDigestLen));
};

CK_RV MC_DigestUpdate
  (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
  CHECK_FUNCTION (C_DigestUpdate);
  return (FUNCTION_CALL (C_DigestUpdate) (hSession, pPart, ulPartLen));
};

CK_RV MC_DigestKey (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
  CHECK_FUNCTION (C_DigestKey);
  return (FUNCTION_CALL (C_DigestKey) (hSession, hKey));
};

CK_RV MC_DigestFinal
  (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
  CHECK_FUNCTION (C_DigestFinal);
  return (FUNCTION_CALL (C_DigestFinal) (hSession, pDigest, pulDigestLen));
};

CK_RV MC_SignInit
  (CK_SESSION_HANDLE hSession,
   CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
  CHECK_FUNCTION (C_SignInit);
  return (FUNCTION_CALL (C_SignInit) (hSession, pMechanism, hKey));
};

CK_RV MC_Sign
  (CK_SESSION_HANDLE hSession,
   CK_BYTE_PTR pData,
   CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
  CHECK_FUNCTION (C_Sign);
  return (FUNCTION_CALL (C_Sign) (hSession,
				  pData,
				  ulDataLen, pSignature, pulSignatureLen));
};

CK_RV MC_SignUpdate
  (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
  CHECK_FUNCTION (C_SignUpdate);
  return (FUNCTION_CALL (C_SignUpdate) (hSession, pPart, ulPartLen));
};

CK_RV MC_SignFinal
  (CK_SESSION_HANDLE hSession,
   CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
  CHECK_FUNCTION (C_SignFinal);
  return (FUNCTION_CALL (C_SignFinal) (hSession,
				       pSignature, pulSignatureLen));
};

CK_RV MC_SignRecoverInit
  (CK_SESSION_HANDLE hSession,
   CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
  CHECK_FUNCTION (C_SignRecoverInit);
  return (FUNCTION_CALL (C_SignRecoverInit) (hSession, pMechanism, hKey));
};

CK_RV MC_SignRecover
  (CK_SESSION_HANDLE hSession,
   CK_BYTE_PTR pData,
   CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
  CHECK_FUNCTION (C_SignRecover);
  return (FUNCTION_CALL (C_SignRecover) (hSession,
					 pData,
					 ulDataLen,
					 pSignature, pulSignatureLen));
};

CK_RV MC_VerifyInit
  (CK_SESSION_HANDLE hSession,
   CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
  CHECK_FUNCTION (C_VerifyInit);
  return (FUNCTION_CALL (C_VerifyInit) (hSession, pMechanism, hKey));
};

CK_RV MC_Verify
  (CK_SESSION_HANDLE hSession,
   CK_BYTE_PTR pData,
   CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
  CHECK_FUNCTION (C_Verify);
  return (FUNCTION_CALL (C_Verify) (hSession,
				    pData,
				    ulDataLen, pSignature, ulSignatureLen));
};

CK_RV MC_VerifyUpdate
  (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
  CHECK_FUNCTION (C_VerifyUpdate);
  return (FUNCTION_CALL (C_VerifyUpdate) (hSession, pPart, ulPartLen));
};

CK_RV MC_VerifyFinal
  (CK_SESSION_HANDLE hSession,
   CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
  CHECK_FUNCTION (C_VerifyFinal);
  return (FUNCTION_CALL (C_VerifyFinal) (hSession,
					 pSignature, ulSignatureLen));
};

CK_RV MC_VerifyRecoverInit
  (CK_SESSION_HANDLE hSession,
   CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
  CHECK_FUNCTION (C_VerifyRecoverInit);
  return (FUNCTION_CALL (C_VerifyRecoverInit) (hSession, pMechanism, hKey));
};

CK_RV MC_VerifyRecover
  (CK_SESSION_HANDLE hSession,
   CK_BYTE_PTR pSignature,
   CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
  CHECK_FUNCTION (C_VerifyRecover);
  return (FUNCTION_CALL (C_VerifyRecover) (hSession,
					   pSignature,
					   ulSignatureLen,
					   pData, pulDataLen));
};

CK_RV MC_DigestEncryptUpdate
  (CK_SESSION_HANDLE hSession,
   CK_BYTE_PTR pPart,
   CK_ULONG ulPartLen,
   CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
  CHECK_FUNCTION (C_DigestEncryptUpdate);
  return (FUNCTION_CALL (C_DigestEncryptUpdate) (hSession,
						 pPart,
						 ulPartLen,
						 pEncryptedPart,
						 pulEncryptedPartLen));
};

CK_RV MC_DecryptDigestUpdate
  (CK_SESSION_HANDLE hSession,
   CK_BYTE_PTR pEncryptedPart,
   CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
  CHECK_FUNCTION (C_DecryptDigestUpdate);
  return (FUNCTION_CALL (C_DecryptDigestUpdate) (hSession,
						 pEncryptedPart,
						 ulEncryptedPartLen,
						 pPart, pulPartLen));
};

CK_RV MC_SignEncryptUpdate
  (CK_SESSION_HANDLE hSession,
   CK_BYTE_PTR pPart,
   CK_ULONG ulPartLen,
   CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
  CHECK_FUNCTION (C_SignEncryptUpdate);
  return (FUNCTION_CALL (C_SignEncryptUpdate) (hSession,
					       pPart,
					       ulPartLen,
					       pEncryptedPart,
					       pulEncryptedPartLen));
};

CK_RV MC_DecryptVerifyUpdate
  (CK_SESSION_HANDLE hSession,
   CK_BYTE_PTR pEncryptedPart,
   CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
  CHECK_FUNCTION (C_DecryptVerifyUpdate);
  return (FUNCTION_CALL (C_DecryptVerifyUpdate) (hSession,
						 pEncryptedPart,
						 ulEncryptedPartLen,
						 pPart, pulPartLen));
};

CK_RV MC_GenerateKey
  (CK_SESSION_HANDLE hSession,
   CK_MECHANISM_PTR pMechanism,
   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
  CHECK_FUNCTION (C_GenerateKey);
  return (FUNCTION_CALL (C_GenerateKey) (hSession,
					 pMechanism,
					 pTemplate, ulCount, phKey));
};

CK_RV MC_GenerateKeyPair
  (CK_SESSION_HANDLE hSession,
   CK_MECHANISM_PTR pMechanism,
   CK_ATTRIBUTE_PTR pPublicKeyTemplate,
   CK_ULONG ulPublicKeyAttributeCount,
   CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
   CK_ULONG ulPrivateKeyAttributeCount,
   CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
  CHECK_FUNCTION (C_GenerateKeyPair);
  return (FUNCTION_CALL (C_GenerateKeyPair) (hSession,
					     pMechanism,
					     pPublicKeyTemplate,
					     ulPublicKeyAttributeCount,
					     pPrivateKeyTemplate,
					     ulPrivateKeyAttributeCount,
					     phPublicKey, phPrivateKey));
};

CK_RV MC_WrapKey
  (CK_SESSION_HANDLE hSession,
   CK_MECHANISM_PTR pMechanism,
   CK_OBJECT_HANDLE hWrappingKey,
   CK_OBJECT_HANDLE hKey,
   CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
  CHECK_FUNCTION (C_WrapKey);
  return (FUNCTION_CALL (C_WrapKey) (hSession,
				     pMechanism,
				     hWrappingKey,
				     hKey, pWrappedKey, pulWrappedKeyLen));
};

CK_RV MC_UnwrapKey
  (CK_SESSION_HANDLE hSession,
   CK_MECHANISM_PTR pMechanism,
   CK_OBJECT_HANDLE hUnwrappingKey,
   CK_BYTE_PTR pWrappedKey,
   CK_ULONG ulWrappedKeyLen,
   CK_ATTRIBUTE_PTR pTemplate,
   CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
  CHECK_FUNCTION (C_UnwrapKey);
  return (FUNCTION_CALL (C_UnwrapKey) (hSession,
				       pMechanism,
				       hUnwrappingKey,
				       pWrappedKey,
				       ulWrappedKeyLen,
				       pTemplate, ulAttributeCount, phKey));
};

CK_RV MC_DeriveKey
  (CK_SESSION_HANDLE hSession,
   CK_MECHANISM_PTR pMechanism,
   CK_OBJECT_HANDLE hBaseKey,
   CK_ATTRIBUTE_PTR pTemplate,
   CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
  CHECK_FUNCTION (C_DeriveKey);
  return (FUNCTION_CALL (C_DeriveKey) (hSession,
				       pMechanism,
				       hBaseKey,
				       pTemplate, ulAttributeCount, phKey));
};

CK_RV MC_SeedRandom
  (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
  CHECK_FUNCTION (C_SeedRandom);
  return (FUNCTION_CALL (C_SeedRandom) (hSession, pSeed, ulSeedLen));
};

CK_RV MC_GenerateRandom
  (CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
  CHECK_FUNCTION (C_GenerateRandom);
  return (FUNCTION_CALL (C_GenerateRandom) (hSession,
					    RandomData, ulRandomLen));
};

CK_RV MC_GetFunctionStatus (CK_SESSION_HANDLE hSession)
{
  CHECK_FUNCTION (C_GetFunctionStatus);
  return (FUNCTION_CALL (C_GetFunctionStatus) (hSession));
};

CK_RV MC_CancelFunction (CK_SESSION_HANDLE hSession)
{
  CHECK_FUNCTION (C_CancelFunction);
  return (FUNCTION_CALL (C_CancelFunction) (hSession));
};

CK_RV MC_WaitForSlotEvent
  (CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pRserved)
{
  CHECK_FUNCTION (C_WaitForSlotEvent);
  return (FUNCTION_CALL (C_WaitForSlotEvent) (flags, pSlot, pRserved));
};
