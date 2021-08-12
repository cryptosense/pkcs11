(** Low-level PKCS#11 bindings. *)

(*
   Module aliases to speed up separate compilation.
   See https://blogs.janestreet.com/better-namespaces-through-module-aliases/

   Note that module A = B is stronger than module A : module type of B.
   It also implies that the types are equal.
 *)

module Data = Pkcs11_data
module CK_ULONG = P11_ulong
module CK_BYTE = Pkcs11_CK_BYTE
module CK_BBOOL = Pkcs11_CK_BBOOL
module CK_UTF8CHAR = Pkcs11_CK_UTF8CHAR
module CK_VOID = Pkcs11_CK_VOID
module CK_SESSION_HANDLE = Pkcs11_CK_SESSION_HANDLE
module CK_OBJECT_HANDLE = Pkcs11_CK_OBJECT_HANDLE
module CK_HW_FEATURE_TYPE = Pkcs11_CK_HW_FEATURE_TYPE
module CK_SLOT_ID = Pkcs11_CK_SLOT_ID
module CK_FLAGS = Pkcs11_CK_FLAGS
module CK_OBJECT_CLASS = Pkcs11_CK_OBJECT_CLASS
module CK_KEY_TYPE = Pkcs11_CK_KEY_TYPE
module CK_VERSION = Pkcs11_CK_VERSION
module CK_BIGINT = P11_bigint
module CK_RV = Pkcs11_CK_RV
module CK_MECHANISM_TYPE = Pkcs11_CK_MECHANISM_TYPE
module CK_RSA_PKCS_MGF_TYPE = Pkcs11_CK_RSA_PKCS_MGF_TYPE
module CK_RSA_PKCS_OAEP_PARAMS = Pkcs11_CK_RSA_PKCS_OAEP_PARAMS
module CK_RSA_PKCS_PSS_PARAMS = Pkcs11_CK_RSA_PKCS_PSS_PARAMS
module CK_KEY_DERIVATION_STRING_DATA = Pkcs11_CK_KEY_DERIVATION_STRING_DATA

module CK_AES_CBC_ENCRYPT_DATA_PARAMS =
  Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_AES_CBC_ENCRYPT_DATA_PARAMS

module CK_DES_CBC_ENCRYPT_DATA_PARAMS =
  Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_DES_CBC_ENCRYPT_DATA_PARAMS

module CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE =
  Pkcs11_CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE
module CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE =
  Pkcs11_CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE
module CK_PKCS5_PBKD2_PARAMS = Pkcs11_CK_PKCS5_PBKD2_PARAMS
module CK_EC_KDF_TYPE = Pkcs11_CK_EC_KDF_TYPE
module CK_ECDH1_DERIVE_PARAMS = Pkcs11_CK_ECDH1_DERIVE_PARAMS
module CK_ECMQV_DERIVE_PARAMS = Pkcs11_CK_ECMQV_DERIVE_PARAMS
module CK_MECHANISM = Pkcs11_CK_MECHANISM
module Key_gen_mechanism = Pkcs11_key_gen_mechanism
module CK_USER_TYPE = Pkcs11_CK_USER_TYPE
module CK_INFO = Pkcs11_CK_INFO
module CK_TOKEN_INFO = Pkcs11_CK_TOKEN_INFO
module CK_SLOT_INFO = Pkcs11_CK_SLOT_INFO
module Slot_list = Pkcs11_slot_list
module CK_MECHANISM_INFO = Pkcs11_CK_MECHANISM_INFO
module CK_SESSION_INFO = Pkcs11_CK_SESSION_INFO
module CK_ATTRIBUTE_TYPE = Pkcs11_CK_ATTRIBUTE_TYPE
module CK_ATTRIBUTE = Pkcs11_CK_ATTRIBUTE
module CK_ATTRIBUTE_SET = Pkcs11_CK_ATTRIBUTE_SET
module Template = Pkcs11_template
module Mechanism_list = Pkcs11_mechanism_list
module CK_AES_CTR_PARAMS = Pkcs11_CK_AES_CTR_PARAMS
module CK_GCM_PARAMS = Pkcs11_CK_GCM_PARAMS

module Initialize_arg : sig
  type _ck_c_initialize_args

  type t = _ck_c_initialize_args Ctypes.structure

  val flags : (CK_FLAGS.t, t) Ctypes.field

  val t : t Ctypes.typ
end

module Nss_initialize_arg : sig
  type _ck_nss_c_initialize_args

  type t = _ck_nss_c_initialize_args Ctypes.structure

  val flags : (CK_FLAGS.t, t) Ctypes.field

  val t : t Ctypes.typ

  (** Only support setting LibraryParameters from the uninitialized type. The format for
      these strings is defined in the Softtoken Specific Parameters section of
      https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/PKCS11/Module_Specs *)
  type u = string

  val make : u -> t
end

type _ck_function_list

type ck_function_list = _ck_function_list Ctypes.structure

val ck_function_list : ck_function_list Ctypes.typ

module CK_NOTIFY : sig
  open Ctypes

  type u

  type t = u ptr

  val u : u typ

  val t : t typ
end

module CK : sig
  module T : sig
    val c_Initialize : (unit Ctypes.ptr -> CK_RV.t) Ctypes.fn

    val c_Finalize : (unit Ctypes.ptr -> CK_RV.t) Ctypes.fn

    val c_GetInfo : (CK_INFO.t Ctypes.ptr -> CK_RV.t) Ctypes.fn

    val c_GetFunctionList :
      (ck_function_list Ctypes.ptr Ctypes.ptr -> CK_RV.t) Ctypes.fn

    val c_GetSlotList :
      (   CK_BBOOL.t
       -> CK_SLOT_ID.t Ctypes.ptr
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_GetSlotInfo :
      (CK_SLOT_ID.t -> CK_SLOT_INFO.t Ctypes.ptr -> CK_RV.t) Ctypes.fn

    val c_GetTokenInfo :
      (CK_SLOT_ID.t -> CK_TOKEN_INFO.t Ctypes.ptr -> CK_RV.t) Ctypes.fn

    val c_GetMechanismList :
      (   CK_SLOT_ID.t
       -> CK_MECHANISM_TYPE.t Ctypes.ptr
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_GetMechanismInfo :
      (   CK_SLOT_ID.t
       -> CK_MECHANISM_TYPE.t
       -> CK_MECHANISM_INFO.t Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_InitToken :
      (   CK_SLOT_ID.t
       -> CK_UTF8CHAR.t Ctypes.ptr
       -> Unsigned.ulong
       -> CK_UTF8CHAR.t Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_InitPIN :
      (   CK_SESSION_HANDLE.t
       -> CK_UTF8CHAR.t Ctypes.ptr
       -> Unsigned.ulong
       -> CK_RV.t)
      Ctypes.fn

    val c_SetPIN :
      (   CK_SESSION_HANDLE.t
       -> CK_UTF8CHAR.t Ctypes.ptr
       -> Unsigned.ulong
       -> CK_UTF8CHAR.t Ctypes.ptr
       -> Unsigned.ulong
       -> CK_RV.t)
      Ctypes.fn

    val c_OpenSession :
      (   CK_SLOT_ID.t
       -> CK_FLAGS.t
       -> unit Ctypes.ptr
       -> CK_NOTIFY.u Ctypes.ptr
       -> CK_SESSION_HANDLE.t Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_CloseSession : (CK_SESSION_HANDLE.t -> CK_RV.t) Ctypes.fn

    val c_CloseAllSessions : (CK_SLOT_ID.t -> CK_RV.t) Ctypes.fn

    val c_GetSessionInfo :
      (CK_SESSION_HANDLE.t -> CK_SESSION_INFO.t Ctypes.ptr -> CK_RV.t) Ctypes.fn

    val c_GetOperationState :
      (   CK_SESSION_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_SetOperationState :
      (   CK_SESSION_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong
       -> CK_OBJECT_HANDLE.t
       -> CK_OBJECT_HANDLE.t
       -> CK_RV.t)
      Ctypes.fn

    val c_Login :
      (   CK_SESSION_HANDLE.t
       -> CK_USER_TYPE.t
       -> CK_UTF8CHAR.t Ctypes.ptr
       -> Unsigned.ulong
       -> CK_RV.t)
      Ctypes.fn

    val c_Logout : (CK_SESSION_HANDLE.t -> CK_RV.t) Ctypes.fn

    val c_CreateObject :
      (   CK_SESSION_HANDLE.t
       -> CK_ATTRIBUTE.t Ctypes.ptr
       -> Unsigned.ulong
       -> CK_OBJECT_HANDLE.t Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_CopyObject :
      (   CK_SESSION_HANDLE.t
       -> CK_OBJECT_HANDLE.t
       -> CK_ATTRIBUTE.t Ctypes.ptr
       -> Unsigned.ulong
       -> CK_OBJECT_HANDLE.t Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_DestroyObject :
      (CK_SESSION_HANDLE.t -> CK_OBJECT_HANDLE.t -> CK_RV.t) Ctypes.fn

    val c_GetObjectSize :
      (   CK_SESSION_HANDLE.t
       -> CK_OBJECT_HANDLE.t
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_GetAttributeValue :
      (   CK_SESSION_HANDLE.t
       -> CK_OBJECT_HANDLE.t
       -> CK_ATTRIBUTE.t Ctypes.ptr
       -> Unsigned.ulong
       -> CK_RV.t)
      Ctypes.fn

    val c_SetAttributeValue :
      (   CK_SESSION_HANDLE.t
       -> CK_OBJECT_HANDLE.t
       -> CK_ATTRIBUTE.t Ctypes.ptr
       -> Unsigned.ulong
       -> CK_RV.t)
      Ctypes.fn

    val c_FindObjectsInit :
      (   CK_SESSION_HANDLE.t
       -> CK_ATTRIBUTE.t Ctypes.ptr
       -> Unsigned.ulong
       -> CK_RV.t)
      Ctypes.fn

    val c_FindObjects :
      (   CK_SESSION_HANDLE.t
       -> CK_OBJECT_HANDLE.t Ctypes.ptr
       -> Unsigned.ulong
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_FindObjectsFinal : (CK_SESSION_HANDLE.t -> CK_RV.t) Ctypes.fn

    val c_EncryptInit :
      (   CK_SESSION_HANDLE.t
       -> CK_MECHANISM.t Ctypes.ptr
       -> CK_OBJECT_HANDLE.t
       -> CK_RV.t)
      Ctypes.fn

    val c_Encrypt :
      (   CK_SESSION_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong
       -> char Ctypes.ptr
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_EncryptUpdate :
      (   CK_SESSION_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong
       -> char Ctypes.ptr
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_EncryptFinal :
      (   CK_SESSION_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_DecryptInit :
      (   CK_SESSION_HANDLE.t
       -> CK_MECHANISM.t Ctypes.ptr
       -> CK_OBJECT_HANDLE.t
       -> CK_RV.t)
      Ctypes.fn

    val c_Decrypt :
      (   CK_SESSION_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong
       -> char Ctypes.ptr
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_DecryptUpdate :
      (   CK_SESSION_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong
       -> char Ctypes.ptr
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_DecryptFinal :
      (   CK_SESSION_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_DigestInit :
      (CK_SESSION_HANDLE.t -> CK_MECHANISM.t Ctypes.ptr -> CK_RV.t) Ctypes.fn

    val c_Digest :
      (   CK_SESSION_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong
       -> char Ctypes.ptr
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_DigestUpdate :
      (CK_SESSION_HANDLE.t -> char Ctypes.ptr -> Unsigned.ulong -> CK_RV.t)
      Ctypes.fn

    val c_DigestKey :
      (CK_SESSION_HANDLE.t -> CK_OBJECT_HANDLE.t -> CK_RV.t) Ctypes.fn

    val c_DigestFinal :
      (   CK_SESSION_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_SignInit :
      (   CK_SESSION_HANDLE.t
       -> CK_MECHANISM.t Ctypes.ptr
       -> CK_OBJECT_HANDLE.t
       -> CK_RV.t)
      Ctypes.fn

    val c_Sign :
      (   CK_SESSION_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong
       -> char Ctypes.ptr
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_SignUpdate :
      (CK_SESSION_HANDLE.t -> char Ctypes.ptr -> Unsigned.ulong -> CK_RV.t)
      Ctypes.fn

    val c_SignFinal :
      (   CK_SESSION_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_SignRecoverInit :
      (   CK_SESSION_HANDLE.t
       -> CK_MECHANISM.t Ctypes.ptr
       -> CK_OBJECT_HANDLE.t
       -> CK_RV.t)
      Ctypes.fn

    val c_SignRecover :
      (   CK_SESSION_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong
       -> char Ctypes.ptr
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_VerifyInit :
      (   CK_SESSION_HANDLE.t
       -> CK_MECHANISM.t Ctypes.ptr
       -> CK_OBJECT_HANDLE.t
       -> CK_RV.t)
      Ctypes.fn

    val c_Verify :
      (   CK_SESSION_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong
       -> char Ctypes.ptr
       -> Unsigned.ulong
       -> CK_RV.t)
      Ctypes.fn

    val c_VerifyUpdate :
      (CK_SESSION_HANDLE.t -> char Ctypes.ptr -> Unsigned.ulong -> CK_RV.t)
      Ctypes.fn

    val c_VerifyFinal :
      (CK_SESSION_HANDLE.t -> char Ctypes.ptr -> Unsigned.ulong -> CK_RV.t)
      Ctypes.fn

    val c_VerifyRecoverInit :
      (   CK_SESSION_HANDLE.t
       -> CK_MECHANISM.t Ctypes.ptr
       -> CK_OBJECT_HANDLE.t
       -> CK_RV.t)
      Ctypes.fn

    val c_VerifyRecover :
      (   CK_SESSION_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong
       -> char Ctypes.ptr
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_DigestEncryptUpdate :
      (   CK_SESSION_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong
       -> char Ctypes.ptr
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_DecryptDigestUpdate :
      (   CK_SESSION_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong
       -> char Ctypes.ptr
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_SignEncryptUpdate :
      (   CK_SESSION_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong
       -> char Ctypes.ptr
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_DecryptVerifyUpdate :
      (   CK_SESSION_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong
       -> char Ctypes.ptr
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_GenerateKey :
      (   CK_SESSION_HANDLE.t
       -> CK_MECHANISM.t Ctypes.ptr
       -> CK_ATTRIBUTE.t Ctypes.ptr
       -> Unsigned.ulong
       -> CK_OBJECT_HANDLE.t Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_GenerateKeyPair :
      (   CK_SESSION_HANDLE.t
       -> CK_MECHANISM.t Ctypes.ptr
       -> CK_ATTRIBUTE.t Ctypes.ptr
       -> Unsigned.ulong
       -> CK_ATTRIBUTE.t Ctypes.ptr
       -> Unsigned.ulong
       -> CK_OBJECT_HANDLE.t Ctypes.ptr
       -> CK_OBJECT_HANDLE.t Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_WrapKey :
      (   CK_SESSION_HANDLE.t
       -> CK_MECHANISM.t Ctypes.ptr
       -> CK_OBJECT_HANDLE.t
       -> CK_OBJECT_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_UnwrapKey :
      (   CK_SESSION_HANDLE.t
       -> CK_MECHANISM.t Ctypes.ptr
       -> CK_OBJECT_HANDLE.t
       -> char Ctypes.ptr
       -> Unsigned.ulong
       -> CK_ATTRIBUTE.t Ctypes.ptr
       -> Unsigned.ulong
       -> CK_OBJECT_HANDLE.t Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_DeriveKey :
      (   CK_SESSION_HANDLE.t
       -> CK_MECHANISM.t Ctypes.ptr
       -> CK_OBJECT_HANDLE.t
       -> CK_ATTRIBUTE.t Ctypes.ptr
       -> Unsigned.ulong
       -> CK_OBJECT_HANDLE.t Ctypes.ptr
       -> CK_RV.t)
      Ctypes.fn

    val c_SeedRandom :
      (CK_SESSION_HANDLE.t -> char Ctypes.ptr -> Unsigned.ulong -> CK_RV.t)
      Ctypes.fn

    val c_GenerateRandom :
      (CK_SESSION_HANDLE.t -> char Ctypes.ptr -> Unsigned.ulong -> CK_RV.t)
      Ctypes.fn

    val c_GetFunctionStatus : (CK_SESSION_HANDLE.t -> CK_RV.t) Ctypes.fn

    val c_CancelFunction : (CK_SESSION_HANDLE.t -> CK_RV.t) Ctypes.fn

    val c_WaitForSlotEvent :
      (CK_FLAGS.t -> CK_SLOT_ID.t Ctypes.ptr -> unit Ctypes.ptr -> CK_RV.t)
      Ctypes.fn
  end

  module Function_list : sig
    type t = (_ck_function_list, [`Struct]) Ctypes.structured

    val version : (CK_VERSION.t, t) Ctypes.field

    val c_Initialize : (unit Ctypes.ptr -> CK_RV.t, t) Ctypes.field

    val c_Finalize : (unit Ctypes.ptr -> CK_RV.t, t) Ctypes.field

    val c_GetInfo : (CK_INFO.t Ctypes.ptr -> CK_RV.t, t) Ctypes.field

    val c_GetFunction_list :
      (ck_function_list Ctypes.ptr Ctypes.ptr -> CK_RV.t, t) Ctypes.field

    val c_GetSlotList :
      (    CK_BBOOL.t
        -> CK_SLOT_ID.t Ctypes.ptr
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_GetSlotInfo :
      (CK_SLOT_ID.t -> CK_SLOT_INFO.t Ctypes.ptr -> CK_RV.t, t) Ctypes.field

    val c_GetTokenInfo :
      (CK_SLOT_ID.t -> CK_TOKEN_INFO.t Ctypes.ptr -> CK_RV.t, t) Ctypes.field

    val c_GetMechanismList :
      (    CK_SLOT_ID.t
        -> CK_MECHANISM_TYPE.t Ctypes.ptr
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_GetMechanismInfo :
      (    CK_SLOT_ID.t
        -> CK_MECHANISM_TYPE.t
        -> CK_MECHANISM_INFO.t Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_InitToken :
      (    CK_SLOT_ID.t
        -> CK_UTF8CHAR.t Ctypes.ptr
        -> Unsigned.ulong
        -> CK_UTF8CHAR.t Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_InitPIN :
      (    CK_SESSION_HANDLE.t
        -> CK_UTF8CHAR.t Ctypes.ptr
        -> Unsigned.ulong
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_SetPIN :
      (    CK_SESSION_HANDLE.t
        -> CK_UTF8CHAR.t Ctypes.ptr
        -> Unsigned.ulong
        -> CK_UTF8CHAR.t Ctypes.ptr
        -> Unsigned.ulong
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_OpenSession :
      (    CK_SLOT_ID.t
        -> CK_FLAGS.t
        -> unit Ctypes.ptr
        -> CK_NOTIFY.t
        -> CK_SESSION_HANDLE.t Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_CloseSession : (CK_SESSION_HANDLE.t -> CK_RV.t, t) Ctypes.field

    val c_CloseAllSessions : (CK_SLOT_ID.t -> CK_RV.t, t) Ctypes.field

    val c_GetSessionInfo :
      ( CK_SESSION_HANDLE.t -> CK_SESSION_INFO.t Ctypes.ptr -> CK_RV.t
      , t )
      Ctypes.field

    val c_GetOperationState :
      (    CK_SESSION_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_SetOperationState :
      (    CK_SESSION_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong
        -> CK_OBJECT_HANDLE.t
        -> CK_OBJECT_HANDLE.t
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_Login :
      (    CK_SESSION_HANDLE.t
        -> CK_USER_TYPE.t
        -> CK_UTF8CHAR.t Ctypes.ptr
        -> Unsigned.ulong
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_Logout : (CK_SESSION_HANDLE.t -> CK_RV.t, t) Ctypes.field

    val c_CreateObject :
      (    CK_SESSION_HANDLE.t
        -> CK_ATTRIBUTE.t Ctypes.ptr
        -> Unsigned.ulong
        -> CK_OBJECT_HANDLE.t Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_CopyObject :
      (    CK_SESSION_HANDLE.t
        -> CK_OBJECT_HANDLE.t
        -> CK_ATTRIBUTE.t Ctypes.ptr
        -> Unsigned.ulong
        -> CK_OBJECT_HANDLE.t Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_DestroyObject :
      (CK_SESSION_HANDLE.t -> CK_OBJECT_HANDLE.t -> CK_RV.t, t) Ctypes.field

    val c_GetObjectSize :
      (    CK_SESSION_HANDLE.t
        -> CK_OBJECT_HANDLE.t
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_GetAttributeValue :
      (    CK_SESSION_HANDLE.t
        -> CK_OBJECT_HANDLE.t
        -> CK_ATTRIBUTE.t Ctypes.ptr
        -> Unsigned.ulong
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_SetAttributeValue :
      (    CK_SESSION_HANDLE.t
        -> CK_OBJECT_HANDLE.t
        -> CK_ATTRIBUTE.t Ctypes.ptr
        -> Unsigned.ulong
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_FindObjectsInit :
      (    CK_SESSION_HANDLE.t
        -> CK_ATTRIBUTE.t Ctypes.ptr
        -> Unsigned.ulong
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_FindObjects :
      (    CK_SESSION_HANDLE.t
        -> CK_OBJECT_HANDLE.t Ctypes.ptr
        -> Unsigned.ulong
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_FindObjectsFinal : (CK_SESSION_HANDLE.t -> CK_RV.t, t) Ctypes.field

    val c_EncryptInit :
      (    CK_SESSION_HANDLE.t
        -> CK_MECHANISM.t Ctypes.ptr
        -> CK_OBJECT_HANDLE.t
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_Encrypt :
      (    CK_SESSION_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong
        -> char Ctypes.ptr
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_EncryptUpdate :
      (    CK_SESSION_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong
        -> char Ctypes.ptr
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_EncryptFinal :
      (    CK_SESSION_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_DecryptInit :
      (    CK_SESSION_HANDLE.t
        -> CK_MECHANISM.t Ctypes.ptr
        -> CK_OBJECT_HANDLE.t
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_Decrypt :
      (    CK_SESSION_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong
        -> char Ctypes.ptr
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_DecryptUpdate :
      (    CK_SESSION_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong
        -> char Ctypes.ptr
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_DecryptFinal :
      (    CK_SESSION_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_DigestInit :
      ( CK_SESSION_HANDLE.t -> CK_MECHANISM.t Ctypes.ptr -> CK_RV.t
      , t )
      Ctypes.field

    val c_Digest :
      (    CK_SESSION_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong
        -> char Ctypes.ptr
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_DigestUpdate :
      ( CK_SESSION_HANDLE.t -> char Ctypes.ptr -> Unsigned.ulong -> CK_RV.t
      , t )
      Ctypes.field

    val c_DigestKey :
      (CK_SESSION_HANDLE.t -> CK_OBJECT_HANDLE.t -> CK_RV.t, t) Ctypes.field

    val c_DigestFinal :
      (    CK_SESSION_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_SignInit :
      (    CK_SESSION_HANDLE.t
        -> CK_MECHANISM.t Ctypes.ptr
        -> CK_OBJECT_HANDLE.t
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_Sign :
      (    CK_SESSION_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong
        -> char Ctypes.ptr
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_SignUpdate :
      ( CK_SESSION_HANDLE.t -> char Ctypes.ptr -> Unsigned.ulong -> CK_RV.t
      , t )
      Ctypes.field

    val c_SignFinal :
      (    CK_SESSION_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_SignRecoverInit :
      (    CK_SESSION_HANDLE.t
        -> CK_MECHANISM.t Ctypes.ptr
        -> CK_OBJECT_HANDLE.t
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_SignRecover :
      (    CK_SESSION_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong
        -> char Ctypes.ptr
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_VerifyInit :
      (    CK_SESSION_HANDLE.t
        -> CK_MECHANISM.t Ctypes.ptr
        -> CK_OBJECT_HANDLE.t
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_Verify :
      (    CK_SESSION_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong
        -> char Ctypes.ptr
        -> Unsigned.ulong
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_VerifyUpdate :
      ( CK_SESSION_HANDLE.t -> char Ctypes.ptr -> Unsigned.ulong -> CK_RV.t
      , t )
      Ctypes.field

    val c_VerifyFinal :
      ( CK_SESSION_HANDLE.t -> char Ctypes.ptr -> Unsigned.ulong -> CK_RV.t
      , t )
      Ctypes.field

    val c_VerifyRecoverInit :
      (    CK_SESSION_HANDLE.t
        -> CK_MECHANISM.t Ctypes.ptr
        -> CK_OBJECT_HANDLE.t
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_VerifyRecover :
      (    CK_SESSION_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong
        -> char Ctypes.ptr
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_DigestEncryptUpdate :
      (    CK_SESSION_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong
        -> char Ctypes.ptr
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_DecryptDigestUpdate :
      (    CK_SESSION_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong
        -> char Ctypes.ptr
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_SignEncryptUpdate :
      (    CK_SESSION_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong
        -> char Ctypes.ptr
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_DecryptVerifyUpdate :
      (    CK_SESSION_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong
        -> char Ctypes.ptr
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_GenerateKey :
      (    CK_SESSION_HANDLE.t
        -> CK_MECHANISM.t Ctypes.ptr
        -> CK_ATTRIBUTE.t Ctypes.ptr
        -> Unsigned.ulong
        -> CK_OBJECT_HANDLE.t Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_GenerateKeyPair :
      (    CK_SESSION_HANDLE.t
        -> CK_MECHANISM.t Ctypes.ptr
        -> CK_ATTRIBUTE.t Ctypes.ptr
        -> Unsigned.ulong
        -> CK_ATTRIBUTE.t Ctypes.ptr
        -> Unsigned.ulong
        -> CK_OBJECT_HANDLE.t Ctypes.ptr
        -> CK_OBJECT_HANDLE.t Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_WrapKey :
      (    CK_SESSION_HANDLE.t
        -> CK_MECHANISM.t Ctypes.ptr
        -> CK_OBJECT_HANDLE.t
        -> CK_OBJECT_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_UnwrapKey :
      (    CK_SESSION_HANDLE.t
        -> CK_MECHANISM.t Ctypes.ptr
        -> CK_OBJECT_HANDLE.t
        -> char Ctypes.ptr
        -> Unsigned.ulong
        -> CK_ATTRIBUTE.t Ctypes.ptr
        -> Unsigned.ulong
        -> CK_OBJECT_HANDLE.t Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_DeriveKey :
      (    CK_SESSION_HANDLE.t
        -> CK_MECHANISM.t Ctypes.ptr
        -> CK_OBJECT_HANDLE.t
        -> CK_ATTRIBUTE.t Ctypes.ptr
        -> Unsigned.ulong
        -> CK_OBJECT_HANDLE.t Ctypes.ptr
        -> CK_RV.t
      , t )
      Ctypes.field

    val c_SeedRandom :
      ( CK_SESSION_HANDLE.t -> char Ctypes.ptr -> Unsigned.ulong -> CK_RV.t
      , t )
      Ctypes.field

    val c_GenerateRandom :
      ( CK_SESSION_HANDLE.t -> char Ctypes.ptr -> Unsigned.ulong -> CK_RV.t
      , t )
      Ctypes.field

    val c_GetFunctionStatus : (CK_SESSION_HANDLE.t -> CK_RV.t, t) Ctypes.field

    val c_CancelFunction : (CK_SESSION_HANDLE.t -> CK_RV.t, t) Ctypes.field

    val c_WaitForSlotEvent :
      ( CK_FLAGS.t -> CK_SLOT_ID.t Ctypes.ptr -> unit Ctypes.ptr -> CK_RV.t
      , t )
      Ctypes.field
  end
end

(** Function lists. *)
module CK_FUNCTION_LIST : sig
  type t = ck_function_list
end

(** Low-level bindings directly wrap the Ctypes function calls. The only functions available
    are the ones in the PKCS#11 interface specification. Functions expect to be passed and
    return CK_* types, and argument types exactly reflect those in the PKCS#11 specification. *)
module type LOW_LEVEL_BINDINGS = sig
  open Ctypes

  val c_GetFunctionList : CK_FUNCTION_LIST.t ptr ptr -> CK_RV.t

  val c_Initialize : CK_VOID.t ptr -> CK_RV.t

  val c_Finalize : CK_VOID.t ptr -> CK_RV.t

  val c_GetInfo : CK_INFO.t ptr -> CK_RV.t

  val c_GetTokenInfo : CK_SLOT_ID.t -> CK_TOKEN_INFO.t ptr -> CK_RV.t

  val c_GetSlotList :
    CK_BBOOL.t -> CK_SLOT_ID.t ptr -> CK_ULONG.t ptr -> CK_RV.t

  val c_GetSlotInfo : CK_SLOT_ID.t -> CK_SLOT_INFO.t ptr -> CK_RV.t

  val c_GetMechanismList :
    CK_SLOT_ID.t -> CK_MECHANISM_TYPE.t ptr -> CK_ULONG.t ptr -> CK_RV.t

  val c_GetMechanismInfo :
    CK_SLOT_ID.t -> CK_MECHANISM_TYPE.t -> CK_MECHANISM_INFO.t ptr -> CK_RV.t

  val c_InitToken :
       CK_SLOT_ID.t
    -> CK_UTF8CHAR.t Ctypes.ptr
    -> CK_ULONG.t
    -> CK_UTF8CHAR.t Ctypes.ptr
    -> CK_RV.t

  val c_InitPIN :
    CK_SESSION_HANDLE.t -> CK_UTF8CHAR.t Ctypes.ptr -> CK_ULONG.t -> CK_RV.t

  val c_SetPIN :
       CK_SESSION_HANDLE.t
    -> CK_UTF8CHAR.t Ctypes.ptr
    -> CK_ULONG.t
    -> CK_UTF8CHAR.t Ctypes.ptr
    -> CK_ULONG.t
    -> CK_RV.t

  val c_OpenSession :
       CK_SLOT_ID.t
    -> CK_FLAGS.t
    -> CK_VOID.t ptr
    -> CK_NOTIFY.t
    -> CK_SESSION_HANDLE.t ptr
    -> CK_RV.t

  val c_CloseSession : CK_SESSION_HANDLE.t -> CK_RV.t

  val c_CloseAllSessions : CK_SLOT_ID.t -> CK_RV.t

  val c_GetSessionInfo : CK_SESSION_HANDLE.t -> CK_SESSION_INFO.t ptr -> CK_RV.t

  val c_GetOperationState :
    CK_SESSION_HANDLE.t -> CK_BYTE.t ptr -> CK_ULONG.t ptr -> CK_RV.t

  val c_SetOperationState :
       CK_SESSION_HANDLE.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t
    -> CK_OBJECT_HANDLE.t
    -> CK_OBJECT_HANDLE.t
    -> CK_RV.t

  val c_Login :
       CK_SESSION_HANDLE.t
    -> CK_USER_TYPE.t
    -> CK_UTF8CHAR.t Ctypes.ptr
    -> CK_ULONG.t
    -> CK_RV.t

  val c_Logout : CK_SESSION_HANDLE.t -> CK_RV.t

  val c_CreateObject :
       CK_SESSION_HANDLE.t
    -> CK_ATTRIBUTE.t ptr
    -> CK_ULONG.t
    -> CK_OBJECT_HANDLE.t ptr
    -> CK_RV.t

  val c_CopyObject :
       CK_SESSION_HANDLE.t
    -> CK_OBJECT_HANDLE.t
    -> CK_ATTRIBUTE.t ptr
    -> CK_ULONG.t
    -> CK_OBJECT_HANDLE.t ptr
    -> CK_RV.t

  val c_DestroyObject : CK_SESSION_HANDLE.t -> CK_OBJECT_HANDLE.t -> CK_RV.t

  val c_GetObjectSize :
    CK_SESSION_HANDLE.t -> CK_OBJECT_HANDLE.t -> CK_ULONG.t ptr -> CK_RV.t

  val c_GetAttributeValue :
       CK_SESSION_HANDLE.t
    -> CK_OBJECT_HANDLE.t
    -> CK_ATTRIBUTE.t ptr
    -> CK_ULONG.t
    -> CK_RV.t

  val c_SetAttributeValue :
       CK_SESSION_HANDLE.t
    -> CK_OBJECT_HANDLE.t
    -> CK_ATTRIBUTE.t ptr
    -> CK_ULONG.t
    -> CK_RV.t

  val c_FindObjectsInit :
    CK_SESSION_HANDLE.t -> CK_ATTRIBUTE.t ptr -> CK_ULONG.t -> CK_RV.t

  val c_FindObjects :
       CK_SESSION_HANDLE.t
    -> CK_OBJECT_HANDLE.t ptr
    -> CK_ULONG.t
    -> CK_ULONG.t ptr
    -> CK_RV.t

  val c_FindObjectsFinal : CK_SESSION_HANDLE.t -> CK_RV.t

  val c_EncryptInit :
    CK_SESSION_HANDLE.t -> CK_MECHANISM.t ptr -> CK_OBJECT_HANDLE.t -> CK_RV.t

  val c_Encrypt :
       CK_SESSION_HANDLE.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t ptr
    -> CK_RV.t

  val c_EncryptUpdate :
       CK_SESSION_HANDLE.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t ptr
    -> CK_RV.t

  val c_EncryptFinal :
    CK_SESSION_HANDLE.t -> CK_BYTE.t ptr -> CK_ULONG.t ptr -> CK_RV.t

  val c_DecryptInit :
    CK_SESSION_HANDLE.t -> CK_MECHANISM.t ptr -> CK_OBJECT_HANDLE.t -> CK_RV.t

  val c_Decrypt :
       CK_SESSION_HANDLE.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t ptr
    -> CK_RV.t

  val c_DecryptUpdate :
       CK_SESSION_HANDLE.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t ptr
    -> CK_RV.t

  val c_DecryptFinal :
    CK_SESSION_HANDLE.t -> CK_BYTE.t ptr -> CK_ULONG.t ptr -> CK_RV.t

  val c_DigestInit : CK_SESSION_HANDLE.t -> CK_MECHANISM.t ptr -> CK_RV.t

  val c_Digest :
       CK_SESSION_HANDLE.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t ptr
    -> CK_RV.t

  val c_DigestUpdate :
    CK_SESSION_HANDLE.t -> CK_BYTE.t ptr -> CK_ULONG.t -> CK_RV.t

  val c_DigestKey : CK_SESSION_HANDLE.t -> CK_OBJECT_HANDLE.t -> CK_RV.t

  val c_DigestFinal :
    CK_SESSION_HANDLE.t -> CK_BYTE.t ptr -> CK_ULONG.t ptr -> CK_RV.t

  val c_SignInit :
    CK_SESSION_HANDLE.t -> CK_MECHANISM.t ptr -> CK_OBJECT_HANDLE.t -> CK_RV.t

  val c_Sign :
       CK_SESSION_HANDLE.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t ptr
    -> CK_RV.t

  val c_SignUpdate :
    CK_SESSION_HANDLE.t -> CK_BYTE.t ptr -> CK_ULONG.t -> CK_RV.t

  val c_SignFinal :
    CK_SESSION_HANDLE.t -> CK_BYTE.t ptr -> CK_ULONG.t ptr -> CK_RV.t

  val c_SignRecoverInit :
    CK_SESSION_HANDLE.t -> CK_MECHANISM.t ptr -> CK_OBJECT_HANDLE.t -> CK_RV.t

  val c_SignRecover :
       CK_SESSION_HANDLE.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t ptr
    -> CK_RV.t

  val c_VerifyInit :
    CK_SESSION_HANDLE.t -> CK_MECHANISM.t ptr -> CK_OBJECT_HANDLE.t -> CK_RV.t

  val c_Verify :
       CK_SESSION_HANDLE.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t
    -> CK_RV.t

  val c_VerifyUpdate :
    CK_SESSION_HANDLE.t -> CK_BYTE.t ptr -> CK_ULONG.t -> CK_RV.t

  val c_VerifyFinal :
    CK_SESSION_HANDLE.t -> CK_BYTE.t ptr -> CK_ULONG.t -> CK_RV.t

  val c_VerifyRecoverInit :
    CK_SESSION_HANDLE.t -> CK_MECHANISM.t ptr -> CK_OBJECT_HANDLE.t -> CK_RV.t

  val c_VerifyRecover :
       CK_SESSION_HANDLE.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t ptr
    -> CK_RV.t

  val c_DigestEncryptUpdate :
       CK_SESSION_HANDLE.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t ptr
    -> CK_RV.t

  val c_DecryptDigestUpdate :
       CK_SESSION_HANDLE.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t ptr
    -> CK_RV.t

  val c_SignEncryptUpdate :
       CK_SESSION_HANDLE.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t ptr
    -> CK_RV.t

  val c_DecryptVerifyUpdate :
       CK_SESSION_HANDLE.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t ptr
    -> CK_RV.t

  val c_GenerateKey :
       CK_SESSION_HANDLE.t
    -> CK_MECHANISM.t ptr
    -> CK_ATTRIBUTE.t ptr
    -> CK_ULONG.t
    -> CK_OBJECT_HANDLE.t ptr
    -> CK_RV.t

  val c_GenerateKeyPair :
       CK_SESSION_HANDLE.t
    -> CK_MECHANISM.t ptr
    -> CK_ATTRIBUTE.t ptr
    -> CK_ULONG.t
    -> CK_ATTRIBUTE.t ptr
    -> CK_ULONG.t
    -> CK_OBJECT_HANDLE.t ptr
    -> CK_OBJECT_HANDLE.t ptr
    -> CK_RV.t

  val c_WrapKey :
       CK_SESSION_HANDLE.t
    -> CK_MECHANISM.t ptr
    -> CK_OBJECT_HANDLE.t
    -> CK_OBJECT_HANDLE.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t ptr
    -> CK_RV.t

  val c_UnwrapKey :
       CK_SESSION_HANDLE.t
    -> CK_MECHANISM.t ptr
    -> CK_OBJECT_HANDLE.t
    -> CK_BYTE.t ptr
    -> CK_ULONG.t
    -> CK_ATTRIBUTE.t ptr
    -> CK_ULONG.t
    -> CK_OBJECT_HANDLE.t ptr
    -> CK_RV.t

  val c_DeriveKey :
       CK_SESSION_HANDLE.t
    -> CK_MECHANISM.t ptr
    -> CK_OBJECT_HANDLE.t
    -> CK_ATTRIBUTE.t ptr
    -> CK_ULONG.t
    -> CK_OBJECT_HANDLE.t ptr
    -> CK_RV.t

  val c_SeedRandom :
    CK_SESSION_HANDLE.t -> CK_BYTE.t ptr -> CK_ULONG.t -> CK_RV.t

  val c_GenerateRandom :
    CK_SESSION_HANDLE.t -> CK_BYTE.t ptr -> CK_ULONG.t -> CK_RV.t

  val c_GetFunctionStatus : CK_SESSION_HANDLE.t -> CK_RV.t

  val c_CancelFunction : CK_SESSION_HANDLE.t -> CK_RV.t

  val c_WaitForSlotEvent :
    CK_FLAGS.t -> CK_SLOT_ID.t ptr -> CK_VOID.t ptr -> CK_RV.t
end

module type CONFIG = sig
  val log_calls : (string * Format.formatter) option

  val library : Dl.library
end

(* Used in the reverse bindings generator. *)
module Fake (X : sig end) : LOW_LEVEL_BINDINGS

(** A low-level wrapper wraps low-level bindings. Only functions in the PKCS#11 interface are
    available. Functions expect to mostly take and return CK_* types, but some arguments are
    named, use ocaml builtin types or are removed for convenience (for example the void ptr
    used by c_Initialize is replaced by unit).

    For low-level bindings that expect to be passed empty structures to populate, the wrapper
    functions will allocate and initialize the structures as appropriate so the caller does not
    have to. *)
module type LOW_LEVEL_WRAPPER = sig
  val c_Initialize : Nss_initialize_arg.t option -> CK_RV.t

  val c_Finalize : unit -> CK_RV.t

  val c_GetInfo : unit -> CK_RV.t * P11_info.t

  (* val c_GetFunctionList : unit -> CK_RV.t * CK_FUNCTION_LIST.t *)
  val c_GetSlotList : bool -> Slot_list.t -> CK_RV.t

  val c_GetSlotInfo : slot:CK_SLOT_ID.t -> CK_RV.t * P11_slot_info.t

  val c_GetTokenInfo : slot:CK_SLOT_ID.t -> CK_RV.t * P11_token_info.t

  val c_GetMechanismList : slot:CK_SLOT_ID.t -> Mechanism_list.t -> CK_RV.t

  val c_GetMechanismInfo :
    slot:CK_SLOT_ID.t -> CK_MECHANISM_TYPE.t -> CK_RV.t * P11_mechanism_info.t

  val c_InitToken : slot:CK_SLOT_ID.t -> pin:string -> label:string -> CK_RV.t

  val c_InitPIN : CK_SESSION_HANDLE.t -> string -> CK_RV.t

  val c_SetPIN :
    CK_SESSION_HANDLE.t -> oldpin:string -> newpin:string -> CK_RV.t

  val c_OpenSession :
    slot:CK_SLOT_ID.t -> flags:CK_FLAGS.t -> CK_RV.t * CK_SESSION_HANDLE.t

  val c_CloseSession : CK_SESSION_HANDLE.t -> CK_RV.t

  val c_CloseAllSessions : slot:CK_SLOT_ID.t -> CK_RV.t

  val c_GetSessionInfo : CK_SESSION_HANDLE.t -> CK_RV.t * P11_session_info.t

  (* val c_GetOperation_state *)
  (* val c_SetOperation_state *)
  val c_Login : CK_SESSION_HANDLE.t -> CK_USER_TYPE.t -> string -> CK_RV.t

  val c_Logout : CK_SESSION_HANDLE.t -> CK_RV.t

  val c_CreateObject :
    CK_SESSION_HANDLE.t -> Template.t -> CK_RV.t * CK_OBJECT_HANDLE.t

  val c_CopyObject :
       CK_SESSION_HANDLE.t
    -> CK_OBJECT_HANDLE.t
    -> Template.t
    -> CK_RV.t * CK_OBJECT_HANDLE.t

  val c_DestroyObject : CK_SESSION_HANDLE.t -> CK_OBJECT_HANDLE.t -> CK_RV.t

  (* val c_GetObjectSize *)
  val c_GetAttributeValue :
    CK_SESSION_HANDLE.t -> CK_OBJECT_HANDLE.t -> Template.t -> CK_RV.t

  val c_SetAttributeValue :
    CK_SESSION_HANDLE.t -> CK_OBJECT_HANDLE.t -> Template.t -> CK_RV.t

  val c_FindObjectsInit : CK_SESSION_HANDLE.t -> Template.t -> CK_RV.t

  val c_FindObjects :
    CK_SESSION_HANDLE.t -> max_size:int -> CK_RV.t * CK_OBJECT_HANDLE.t list

  val c_FindObjectsFinal : CK_SESSION_HANDLE.t -> CK_RV.t

  val c_EncryptInit :
    CK_SESSION_HANDLE.t -> CK_MECHANISM.t -> CK_OBJECT_HANDLE.t -> CK_RV.t

  val c_Encrypt : CK_SESSION_HANDLE.t -> src:Data.t -> tgt:Data.t -> CK_RV.t

  val c_EncryptUpdate : CK_SESSION_HANDLE.t -> Data.t -> Data.t -> CK_RV.t

  val c_EncryptFinal : CK_SESSION_HANDLE.t -> Data.t -> CK_RV.t

  val c_DecryptInit :
    CK_SESSION_HANDLE.t -> CK_MECHANISM.t -> CK_OBJECT_HANDLE.t -> CK_RV.t

  val c_Decrypt : CK_SESSION_HANDLE.t -> src:Data.t -> tgt:Data.t -> CK_RV.t

  val c_DecryptUpdate : CK_SESSION_HANDLE.t -> Data.t -> Data.t -> CK_RV.t

  val c_DecryptFinal : CK_SESSION_HANDLE.t -> Data.t -> CK_RV.t

  val c_DigestInit : CK_SESSION_HANDLE.t -> CK_MECHANISM.t -> CK_RV.t

  val c_Digest : CK_SESSION_HANDLE.t -> Data.t -> Data.t -> CK_RV.t

  val c_DigestUpdate : CK_SESSION_HANDLE.t -> Data.t -> CK_RV.t

  val c_DigestKey : CK_SESSION_HANDLE.t -> CK_OBJECT_HANDLE.t -> CK_RV.t

  val c_DigestFinal : CK_SESSION_HANDLE.t -> Data.t -> CK_RV.t

  val c_SignInit :
    CK_SESSION_HANDLE.t -> CK_MECHANISM.t -> CK_OBJECT_HANDLE.t -> CK_RV.t

  val c_Sign : CK_SESSION_HANDLE.t -> src:Data.t -> tgt:Data.t -> CK_RV.t

  val c_SignUpdate : CK_SESSION_HANDLE.t -> Data.t -> CK_RV.t

  val c_SignFinal : CK_SESSION_HANDLE.t -> Data.t -> CK_RV.t

  val c_SignRecoverInit :
    CK_SESSION_HANDLE.t -> CK_MECHANISM.t -> CK_OBJECT_HANDLE.t -> CK_RV.t

  val c_SignRecover : CK_SESSION_HANDLE.t -> src:Data.t -> tgt:Data.t -> CK_RV.t

  val c_VerifyInit :
    CK_SESSION_HANDLE.t -> CK_MECHANISM.t -> CK_OBJECT_HANDLE.t -> CK_RV.t

  val c_Verify :
    CK_SESSION_HANDLE.t -> signed:Data.t -> signature:Data.t -> CK_RV.t

  val c_VerifyUpdate : CK_SESSION_HANDLE.t -> Data.t -> CK_RV.t

  val c_VerifyFinal : CK_SESSION_HANDLE.t -> Data.t -> CK_RV.t

  val c_VerifyRecoverInit :
    CK_SESSION_HANDLE.t -> CK_MECHANISM.t -> CK_OBJECT_HANDLE.t -> CK_RV.t

  val c_VerifyRecover :
    CK_SESSION_HANDLE.t -> signature:Data.t -> signed:Data.t -> CK_RV.t

  val c_DigestEncryptUpdate :
    CK_SESSION_HANDLE.t -> src:Data.t -> tgt:Data.t -> CK_RV.t

  val c_DecryptDigestUpdate :
    CK_SESSION_HANDLE.t -> src:Data.t -> tgt:Data.t -> CK_RV.t

  val c_SignEncryptUpdate :
    CK_SESSION_HANDLE.t -> src:Data.t -> tgt:Data.t -> CK_RV.t

  val c_DecryptVerifyUpdate :
    CK_SESSION_HANDLE.t -> src:Data.t -> tgt:Data.t -> CK_RV.t
  (** {2 Key Management} *)

  val c_GenerateKey :
       CK_SESSION_HANDLE.t
    -> CK_MECHANISM.t
    -> Template.t
    -> CK_RV.t * CK_OBJECT_HANDLE.t

  val c_GenerateKeyPair :
       CK_SESSION_HANDLE.t
    -> CK_MECHANISM.t
    -> public:Template.t
    -> privat:Template.t
    -> CK_RV.t * CK_OBJECT_HANDLE.t * CK_OBJECT_HANDLE.t

  val c_WrapKey :
       CK_SESSION_HANDLE.t
    -> CK_MECHANISM.t
    -> wrapping_key:CK_OBJECT_HANDLE.t
    -> key:CK_OBJECT_HANDLE.t
    -> wrapped_key:Data.t
    -> CK_RV.t

  val c_UnwrapKey :
       CK_SESSION_HANDLE.t
    -> CK_MECHANISM.t
    -> unwrapping_key:CK_OBJECT_HANDLE.t
    -> wrapped_key:Data.t
    -> Template.t
    -> CK_RV.t * CK_OBJECT_HANDLE.t

  val c_DeriveKey :
       CK_SESSION_HANDLE.t
    -> CK_MECHANISM.t
    -> CK_OBJECT_HANDLE.t
    -> Template.t
    -> CK_RV.t * CK_OBJECT_HANDLE.t
end

module Wrap_low_level_bindings (X : LOW_LEVEL_BINDINGS) : LOW_LEVEL_WRAPPER

val load_driver :
     ?log_calls:string * Format.formatter
  -> ?on_unknown:(string -> unit)
  -> ?load_mode:P11.Load_mode.t
  -> string
  -> (module LOW_LEVEL_BINDINGS)
(** [on_unknown] will be called with a warning message
   when unsupported codes are encountered. *)
