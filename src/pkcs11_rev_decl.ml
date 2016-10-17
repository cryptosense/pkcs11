(* All functions declared here are named UC_ where the U stands for unlocked.
   The actual C_ functions are proxies to this with a mutex lock added.
*)

(* toplevel ref to store value that should not be garbage collected *)
let roots = ref []

module Rev_bindings(Callback : Pkcs11.RAW)(I: Cstubs_inverted.INTERNAL) = struct

  open Pkcs11

  let declare name signature cb =
    (* Format.eprintf "registering function %S@." name; *)
    roots := Obj.repr cb :: !roots;
    I.internal name signature cb

  let c_Initialize = declare "UC_Initialize"
      CK.T.c_Initialize Callback.c_Initialize

  let c_Finalize = declare "UC_Finalize"
      CK.T.c_Finalize Callback.c_Finalize

  let c_GetInfo = declare "UC_GetInfo"
      CK.T.c_GetInfo Callback.c_GetInfo

  let c_GetTokenInfo = declare "UC_GetTokenInfo"
      CK.T.c_GetTokenInfo Callback.c_GetTokenInfo

  (* let c_GetFunctionList = declare "UC_GetFunctionList" *)
  (*     CK.T.c_GetFunctionList Callback.c_GetFunctionList *)

  let c_GetSlotList = declare "UC_GetSlotList"
      CK.T.c_GetSlotList Callback.c_GetSlotList

  let c_GetSlotInfo = declare "UC_GetSlotInfo"
      CK.T.c_GetSlotInfo Callback.c_GetSlotInfo

  let c_GetMechanismList = declare "UC_GetMechanismList"
      CK.T.c_GetMechanismList Callback.c_GetMechanismList

  let c_GetMechanismInfo = declare "UC_GetMechanismInfo"
      CK.T.c_GetMechanismInfo Callback.c_GetMechanismInfo

  let c_InitToken = declare "UC_InitToken"
      CK.T.c_InitToken Callback.c_InitToken

  let c_InitPIN = declare "UC_InitPIN"
      CK.T.c_InitPIN Callback.c_InitPIN

  let c_SetPIN = declare "UC_SetPIN"
      CK.T.c_SetPIN Callback.c_SetPIN


(******************************************************************************)
(*                             Session Management                             *)
(******************************************************************************)

  let c_OpenSession = declare "UC_OpenSession"
      CK.T.c_OpenSession Callback.c_OpenSession

  let c_CloseSession = declare "UC_CloseSession"
      CK.T.c_CloseSession Callback.c_CloseSession

  let c_CloseAllSessions = declare "UC_CloseAllSessions"
      CK.T.c_CloseAllSessions Callback.c_CloseAllSessions

  let c_GetSessionInfo = declare "UC_GetSessionInfo"
      CK.T.c_GetSessionInfo Callback.c_GetSessionInfo
  let c_GetOperationState = declare "UC_GetOperationState" CK.T.c_GetOperationState Callback.c_GetOperationState
  let c_SetOperationState = declare "UC_SetOperationState" CK.T.c_SetOperationState Callback.c_SetOperationState
  let c_Login = declare "UC_Login"
      CK.T.c_Login Callback.c_Login

  let c_Logout = declare "UC_Logout"
      CK.T.c_Logout Callback.c_Logout

(******************************************************************************)
(*                                Object Management                           *)
(******************************************************************************)

  let c_CreateObject = declare "UC_CreateObject"
      CK.T.c_CreateObject Callback.c_CreateObject

  let c_CopyObject = declare "UC_CopyObject"
      CK.T.c_CopyObject Callback.c_CopyObject

  let c_DestroyObject = declare "UC_DestroyObject"
      CK.T.c_DestroyObject Callback.c_DestroyObject
  let c_GetObjectSize = declare "UC_GetObjectSize" CK.T.c_GetObjectSize Callback.c_GetObjectSize
  let c_GetAttributeValue = declare "UC_GetAttributeValue"
      CK.T.c_GetAttributeValue Callback.c_GetAttributeValue

  let c_SetAttributeValue = declare "UC_SetAttributeValue"
      CK.T.c_SetAttributeValue Callback.c_SetAttributeValue

  let c_FindObjectsInit = declare "UC_FindObjectsInit"
      CK.T.c_FindObjectsInit Callback.c_FindObjectsInit

  let c_FindObjects = declare "UC_FindObjects"
      CK.T.c_FindObjects Callback.c_FindObjects

  let c_FindObjectsFinal = declare "UC_FindObjectsFinal"
      CK.T.c_FindObjectsFinal Callback.c_FindObjectsFinal

(******************************************************************************)
(*                          Encryption and decryption                         *)
(******************************************************************************)

  let c_EncryptInit = declare "UC_EncryptInit"
      CK.T.c_EncryptInit Callback.c_EncryptInit

  let c_Encrypt = declare "UC_Encrypt"
      CK.T.c_Encrypt Callback.c_Encrypt
  let c_EncryptUpdate = declare "UC_EncryptUpdate" CK.T.c_EncryptUpdate Callback.c_EncryptUpdate
  let c_EncryptFinal = declare "UC_EncryptFinal" CK.T.c_EncryptFinal Callback.c_EncryptFinal

  let c_DecryptInit = declare "UC_DecryptInit"
      CK.T.c_DecryptInit Callback.c_DecryptInit

  let c_Decrypt = declare "UC_Decrypt"
      CK.T.c_Decrypt Callback.c_Decrypt
  let c_DecryptUpdate = declare "UC_DecryptUpdate" CK.T.c_DecryptUpdate Callback.c_DecryptUpdate
  let c_DecryptFinal = declare "UC_DecryptFinal" CK.T.c_DecryptFinal Callback.c_DecryptFinal
  let c_DigestInit = declare "UC_DigestInit" CK.T.c_DigestInit Callback.c_DigestInit
  let c_Digest = declare "UC_Digest" CK.T.c_Digest Callback.c_Digest
  let c_DigestUpdate = declare "UC_DigestUpdate" CK.T.c_DigestUpdate Callback.c_DigestUpdate
  let c_DigestKey = declare "UC_DigestKey" CK.T.c_DigestKey Callback.c_DigestKey
  let c_DigestFinal = declare "UC_DigestFinal" CK.T.c_DigestFinal Callback.c_DigestFinal

(******************************************************************************)
(*                             Signing and MACing                             *)
(******************************************************************************)

  let c_SignInit = declare "UC_SignInit"
      CK.T.c_SignInit Callback.c_SignInit

  let c_Sign = declare "UC_Sign"
      CK.T.c_Sign Callback.c_Sign

  let c_SignUpdate = declare "UC_SignUpdate"
      CK.T.c_SignUpdate Callback.c_SignUpdate

  let c_SignFinal = declare "UC_SignFinal"
      CK.T.c_SignFinal Callback.c_SignFinal

  let c_SignRecoverInit = declare "UC_SignRecoverInit"
      CK.T.c_SignRecoverInit Callback.c_SignRecoverInit

  let c_SignRecover = declare "UC_SignRecover"
      CK.T.c_SignRecover Callback.c_SignRecover

  let c_VerifyInit = declare "UC_VerifyInit"
      CK.T.c_VerifyInit Callback.c_VerifyInit

  let c_Verify = declare "UC_Verify"
      CK.T.c_Verify Callback.c_Verify
  let c_VerifyUpdate = declare "UC_VerifyUpdate" CK.T.c_VerifyUpdate Callback.c_VerifyUpdate
  let c_VerifyFinal = declare "UC_VerifyFinal" CK.T.c_VerifyFinal Callback.c_VerifyFinal

  let c_VerifyRecoverInit = declare "UC_VerifyRecoverInit"
      CK.T.c_VerifyRecoverInit Callback.c_VerifyRecoverInit

  let c_VerifyRecover = declare "UC_VerifyRecover"
      CK.T.c_VerifyRecover Callback.c_VerifyRecover
  let c_DigestEncryptUpdate = declare "UC_DigestEncryptUpdate" CK.T.c_DigestEncryptUpdate Callback.c_DigestEncryptUpdate
  let c_DecryptDigestUpdate = declare "UC_DecryptDigestUpdate" CK.T.c_DecryptDigestUpdate Callback.c_DecryptDigestUpdate
  let c_SignEncryptUpdate = declare "UC_SignEncryptUpdate" CK.T.c_SignEncryptUpdate Callback.c_SignEncryptUpdate
  let c_DecryptVerifyUpdate = declare "UC_DecryptVerifyUpdate" CK.T.c_DecryptVerifyUpdate Callback.c_DecryptVerifyUpdate

(******************************************************************************)
(*                               Key management                               *)
(******************************************************************************)

  let c_GenerateKey = declare "UC_GenerateKey"
      CK.T.c_GenerateKey Callback.c_GenerateKey

  let c_GenerateKeyPair = declare "UC_GenerateKeyPair"
      CK.T.c_GenerateKeyPair Callback.c_GenerateKeyPair

  let c_WrapKey = declare "UC_WrapKey"
      CK.T.c_WrapKey Callback.c_WrapKey

  let c_UnwrapKey = declare "UC_UnwrapKey"
      CK.T.c_UnwrapKey Callback.c_UnwrapKey

  let c_DeriveKey = declare "UC_DeriveKey"
      CK.T.c_DeriveKey Callback.c_DeriveKey

  let c_SeedRandom = declare "UC_SeedRandom" CK.T.c_SeedRandom Callback.c_SeedRandom
  let c_GenerateRandom = declare "UC_GenerateRandom" CK.T.c_GenerateRandom Callback.c_GenerateRandom
  let c_GetFunctionStatus = declare "UC_GetFunctionStatus" CK.T.c_GetFunctionStatus Callback.c_GetFunctionStatus
  let c_CancelFunction = declare "UC_CancelFunction" CK.T.c_CancelFunction Callback.c_CancelFunction
  let c_WaitForSlotEvent = declare "UC_WaitForSlotEvent" CK.T.c_WaitForSlotEvent Callback.c_WaitForSlotEvent
end
