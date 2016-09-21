open Ctypes

open Pkcs11_types

module C (F : Cstubs.FOREIGN) = struct
  open F

  module T = CK.TF(F)

  (* We add two extra functions on top of PKCS11 to load a PKCS11
     module, and to unload it.  *)
  let c_LoadModule = foreign "MC_LoadModule" (string @-> returning ck_rv)
  let c_UnloadModule = foreign "MC_UnloadModule" (void @-> returning ck_rv)

  (* PKCS11 functions *)

  let c_GetFunctionList =  foreign "MC_GetFunctionList" T.c_GetFunctionList
  let c_Initialize = foreign "MC_Initialize" T.c_Initialize
  let c_Finalize = foreign "MC_Finalize" T.c_Finalize
  let c_GetInfo  = foreign "MC_GetInfo" T.c_GetInfo
  let c_GetTokenInfo = foreign "MC_GetTokenInfo" T.c_GetTokenInfo
  let c_GetSlotList = foreign "MC_GetSlotList" T.c_GetSlotList
  let c_GetSlotInfo = foreign "MC_GetSlotInfo" T.c_GetSlotInfo
  let c_GetMechanismList = foreign "MC_GetMechanismList" T.c_GetMechanismList
  let c_GetMechanismInfo = foreign "MC_GetMechanismInfo" T.c_GetMechanismInfo
  let c_InitToken = foreign "MC_InitToken" T.c_InitToken
  let c_InitPIN = foreign "MC_InitPIN" T.c_InitPIN
  let c_SetPIN = foreign "MC_SetPIN" T.c_SetPIN
  let c_OpenSession  = foreign "MC_OpenSession" T.c_OpenSession
  let c_CloseSession  = foreign "MC_CloseSession" T.c_CloseSession
  let c_CloseAllSessions  = foreign "MC_CloseAllSessions" T.c_CloseAllSessions
  let c_GetSessionInfo  = foreign "MC_GetSessionInfo" T.c_GetSessionInfo
  let c_GetOperationState = foreign "MC_GetOperationState" T.c_GetOperationState
  let c_SetOperationState = foreign "MC_SetOperationState" T.c_SetOperationState
  let c_Login = foreign "MC_Login" T.c_Login
  let c_Logout = foreign "MC_Logout" T.c_Logout
  let c_CreateObject = foreign "MC_CreateObject" T.c_CreateObject
  let c_CopyObject = foreign "MC_CopyObject" T.c_CopyObject
  let c_DestroyObject = foreign "MC_DestroyObject" T.c_DestroyObject
  let c_GetObjectSize = foreign "MC_GetObjectSize" T.c_GetObjectSize
  let c_GetAttributeValue = foreign "MC_GetAttributeValue" T.c_GetAttributeValue
  let c_SetAttributeValue = foreign "MC_SetAttributeValue" T.c_SetAttributeValue
  let c_FindObjectsInit = foreign "MC_FindObjectsInit" T.c_FindObjectsInit
  let c_FindObjects = foreign "MC_FindObjects" T.c_FindObjects
  let c_FindObjectsFinal = foreign "MC_FindObjectsFinal" T.c_FindObjectsFinal
  let c_EncryptInit = foreign "MC_EncryptInit" T.c_EncryptInit
  let c_Encrypt = foreign "MC_Encrypt" T.c_Encrypt
  let c_EncryptUpdate = foreign "MC_EncryptUpdate" T.c_EncryptUpdate
  let c_EncryptFinal = foreign "MC_EncryptFinal" T.c_EncryptFinal
  let c_DecryptInit = foreign "MC_DecryptInit" T.c_DecryptInit
  let c_Decrypt = foreign "MC_Decrypt" T.c_Decrypt
  let c_DecryptUpdate = foreign "MC_DecryptUpdate" T.c_DecryptUpdate
  let c_DecryptFinal = foreign "MC_DecryptFinal" T.c_DecryptFinal
  let c_DigestInit = foreign "MC_DigestInit" T.c_DigestInit
  let c_Digest = foreign "MC_Digest" T.c_Digest
  let c_DigestUpdate = foreign "MC_DigestUpdate" T.c_DigestUpdate
  let c_DigestKey = foreign "MC_DigestKey" T.c_DigestKey
  let c_DigestFinal = foreign "MC_DigestFinal" T.c_DigestFinal
  let c_SignInit = foreign "MC_SignInit" T.c_SignInit
  let c_Sign = foreign "MC_Sign" T.c_Sign
  let c_SignUpdate = foreign "MC_SignUpdate" T.c_SignUpdate
  let c_SignFinal = foreign "MC_SignFinal" T.c_SignFinal
  let c_SignRecoverInit = foreign "MC_SignRecoverInit" T.c_SignRecoverInit
  let c_SignRecover = foreign "MC_SignRecover" T.c_SignRecover
  let c_VerifyInit = foreign "MC_VerifyInit" T.c_VerifyInit
  let c_Verify = foreign "MC_Verify" T.c_Verify
  let c_VerifyUpdate = foreign "MC_VerifyUpdate" T.c_VerifyUpdate
  let c_VerifyFinal = foreign "MC_VerifyFinal" T.c_VerifyFinal
  let c_VerifyRecoverInit = foreign "MC_VerifyRecoverInit" T.c_VerifyRecoverInit
  let c_VerifyRecover = foreign "MC_VerifyRecover" T.c_VerifyRecover
  let c_DigestEncryptUpdate = foreign "MC_DigestEncryptUpdate" T.c_DigestEncryptUpdate
  let c_DecryptDigestUpdate = foreign "MC_DecryptDigestUpdate" T.c_DecryptDigestUpdate
  let c_SignEncryptUpdate = foreign "MC_SignEncryptUpdate" T.c_SignEncryptUpdate
  let c_DecryptVerifyUpdate = foreign "MC_DecryptVerifyUpdate" T.c_DecryptVerifyUpdate
  let c_GenerateKey =  foreign "MC_GenerateKey" T.c_GenerateKey
  let c_GenerateKeyPair = foreign "MC_GenerateKeyPair" T.c_GenerateKeyPair
  let c_WrapKey = foreign "MC_WrapKey" T.c_WrapKey
  let c_UnwrapKey = foreign "MC_UnwrapKey" T.c_UnwrapKey
  let c_DeriveKey = foreign "MC_DeriveKey" T.c_DeriveKey
  let c_SeedRandom = foreign "MC_SeedRandom" T.c_SeedRandom
  let c_GenerateRandom = foreign "MC_GenerateRandom" T.c_GenerateRandom
  let c_GetFunctionStatus = foreign "MC_GetFunctionStatus" T.c_GetFunctionStatus
  let c_CancelFunction = foreign "MC_CancelFunction" T.c_CancelFunction
  let c_WaitForSlotEvent = foreign "MC_WaitForSlotEvent" T.c_WaitForSlotEvent
end
