(** Types used in the API *)
open Ctypes

(** The bindings come in two flavours. The first one is the Direct
    mode, in which each function from the PKCS11.h header are binded
    directly. The second one is the Indirect mode, in which we use an
    indirection through the list of function returned by
    GetFunctionList. *)

(** CONVENTIONS.

    _t is a type variable used to constrain the [Ctypes] representation.  It
    appears in [Pkcs11.CK_VERSION], for instance. However, only [t] is exported,
    which is defined as [_t structure]. For some modules, it is quite easy to
    work with [t] seen as an abstract type.  For other modules, the higher-level
    type such as [P11.Version.t] is more practical.

    Where appropriate, we provide the following functions:

    - [create: unit -> Pkcs11.CK_x.t]: Allocate a new object of type t (possibly, not
      initialized).
    - [allocate: Pkcs11.CK_x.t -> unit]: Update the object in place by allocating memory for
      its various fields.
    - [view: Pkcs11.CK_x.t -> P11.X.t]: Build the high-level version of the data
      represented by the argument.
    - [make: P11.X.t -> Pkcs11.CK_x.t]: Build the Ctypes version of the data
      represented by [P11.X.t].

    N.B. The last two functions raise the question of why we are not using
    Ctypes views. The problem is that for some functions of the PKCS#11
    interface, we have to make several calls to the API to build a proper
    [Pkcs11.CK_x.t], that could then be used to build a [P11.X.t].
*)

module CK_ULONG = P11_ulong
module CK_BYTE = Pkcs11_CK_BYTE
module CK_BBOOL = Pkcs11_CK_BBOOL
module CK_UTF8CHAR = Pkcs11_CK_UTF8CHAR
module CK_VOID = Pkcs11_CK_VOID
module CK_FLAGS = Pkcs11_CK_FLAGS
module Data = Pkcs11_data
module CK_OBJECT_CLASS = Pkcs11_CK_OBJECT_CLASS
module CK_KEY_TYPE = Pkcs11_CK_KEY_TYPE
module CK_VERSION = Pkcs11_CK_VERSION
module CK_SESSION_HANDLE = Pkcs11_CK_SESSION_HANDLE
module CK_OBJECT_HANDLE = Pkcs11_CK_OBJECT_HANDLE
module CK_HW_FEATURE_TYPE = Pkcs11_CK_HW_FEATURE_TYPE
module CK_SLOT_ID = Pkcs11_CK_SLOT_ID
module CK_SLOT_INFO = Pkcs11_CK_SLOT_INFO
module Slot_list = Pkcs11_slot_list
module CK_MECHANISM_INFO = Pkcs11_CK_MECHANISM_INFO
module CK_SESSION_INFO = Pkcs11_CK_SESSION_INFO
module CK_BIGINT = P11_bigint
module CK_RV = Pkcs11_CK_RV
module CK_MECHANISM_TYPE = Pkcs11_CK_MECHANISM_TYPE
module Key_gen_mechanism = Pkcs11_key_gen_mechanism
module CK_RSA_PKCS_MGF_TYPE = Pkcs11_CK_RSA_PKCS_MGF_TYPE
module CK_RSA_PKCS_OAEP_PARAMS = Pkcs11_CK_RSA_PKCS_OAEP_PARAMS
module CK_RSA_PKCS_PSS_PARAMS = Pkcs11_CK_RSA_PKCS_PSS_PARAMS
module CK_KEY_DERIVATION_STRING_DATA = Pkcs11_CK_KEY_DERIVATION_STRING_DATA

module CK_DES_CBC_ENCRYPT_DATA_PARAMS =
  Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_DES_CBC_ENCRYPT_DATA_PARAMS

module CK_AES_CBC_ENCRYPT_DATA_PARAMS =
  Pkcs11_CBC_ENCRYPT_DATA_PARAMS.CK_AES_CBC_ENCRYPT_DATA_PARAMS

module CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE =
  Pkcs11_CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE
module CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE =
  Pkcs11_CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE
module CK_PKCS5_PBKD2_PARAMS = Pkcs11_CK_PKCS5_PBKD2_PARAMS
module CK_EC_KDF_TYPE = Pkcs11_CK_EC_KDF_TYPE
module CK_ECDH1_DERIVE_PARAMS = Pkcs11_CK_ECDH1_DERIVE_PARAMS
module CK_ECMQV_DERIVE_PARAMS = Pkcs11_CK_ECMQV_DERIVE_PARAMS
module CK_MECHANISM = Pkcs11_CK_MECHANISM
module CK_USER_TYPE = Pkcs11_CK_USER_TYPE
module CK_INFO = Pkcs11_CK_INFO
module CK_TOKEN_INFO = Pkcs11_CK_TOKEN_INFO
module CK_ATTRIBUTE_TYPE = Pkcs11_CK_ATTRIBUTE_TYPE
module CK_ATTRIBUTE = Pkcs11_CK_ATTRIBUTE
module Template = Pkcs11_template
module Mechanism_list = Pkcs11_mechanism_list
module CK_ATTRIBUTE_SET = Pkcs11_CK_ATTRIBUTE_SET
module CK_AES_CTR_PARAMS = Pkcs11_CK_AES_CTR_PARAMS
module CK_GCM_PARAMS = Pkcs11_CK_GCM_PARAMS

let ck_byte = CK_BYTE.typ

let utf8char = ck_byte

let ck_utf8char = char

let ck_bbool = ck_byte

let ck_flags = CK_FLAGS.typ

let ck_object_class = CK_OBJECT_CLASS.typ

let ck_version = CK_VERSION.ck_version

let ck_session_handle = CK_SESSION_HANDLE.typ

let ck_object_handle = CK_OBJECT_HANDLE.typ

let ck_hw_feature_type = CK_HW_FEATURE_TYPE.typ

let ck_slot_id = CK_SLOT_ID.typ

let ck_slot_info = CK_SLOT_INFO.ck_slot_info

let ck_mechanism_info = CK_MECHANISM_INFO.ck_mechanism_info

let ck_session_info = CK_SESSION_INFO.ck_session_info

let ck_rv = CK_RV.typ

let ck_mechanism_type = CK_MECHANISM_TYPE.typ

let ck_rsa_pkcs_mgf_type = CK_RSA_PKCS_MGF_TYPE.typ

let ck_pkcs5_pbkdf2_salt_source_type = CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE.typ

let ck_pkcs5_pbkd2_pseudo_random_function_type =
  CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE.typ

let ck_mechanism : CK_MECHANISM.t typ = CK_MECHANISM.ck_mechanism

let ck_user_type = CK_USER_TYPE.typ

let ck_info = CK_INFO.ck_info

let ck_token_info = CK_TOKEN_INFO.ck_token_info

let ck_attribute_type = CK_ATTRIBUTE_TYPE.typ

let ck_attribute = CK_ATTRIBUTE.ck_attribute

type template = Template.t

module Initialize_arg = struct
  let mutex = void

  type _ck_c_initialize_args

  type t = _ck_c_initialize_args structure

  let t : t typ = structure "CK_C_INITIALIZE_ARGS"

  let ( -: ) ty label = Ctypes_helpers.smart_field t label ty

  let f typ = Foreign.funptr (typ @-> returning ck_rv)

  let createMutex = f (ptr (ptr mutex)) -: "CreateMutex"

  let destroyMutex = f (ptr mutex) -: "DestroyMutex"

  let lockMutex = f (ptr mutex) -: "LockMutex"

  let unlockMutex = f (ptr mutex) -: "UnlockMutex"

  let flags = ck_flags -: "flags"

  let pReserved = ptr void -: "pReserved"

  let () = seal t
end

module Nss_initialize_arg = struct
  let mutex = void

  type _ck_nss_c_initialize_args

  type t = _ck_nss_c_initialize_args structure

  let t : t typ = structure "CK_NSS_C_INITIALIZE_ARGS"

  let ( -: ) ty label = Ctypes_helpers.smart_field t label ty

  let f typ = Foreign.funptr_opt (typ @-> returning ck_rv)

  let createMutex = f (ptr (ptr mutex)) -: "CreateMutex"

  let destroyMutex = f (ptr mutex) -: "DestroyMutex"

  let lockMutex = f (ptr mutex) -: "LockMutex"

  let unlockMutex = f (ptr mutex) -: "UnlockMutex"

  let flags = ck_flags -: "flags"

  let libraryParameters = Ctypes.string_opt -: "LibraryParameters"

  let pReserved = ptr void -: "pReserved"

  let () = seal t

  type u = string

  let make (params : u) =
    let t = Ctypes.make t in
    Ctypes.setf t createMutex None;
    Ctypes.setf t destroyMutex None;
    Ctypes.setf t lockMutex None;
    Ctypes.setf t unlockMutex None;
    Ctypes.setf t flags Pkcs11_CK_FLAGS._CKF_OS_LOCKING_OK;
    Ctypes.setf t libraryParameters (Some params);
    Ctypes.setf t pReserved Ctypes.null;
    t
end

(******************************************************************************)
(*                                  Functions                                 *)
(******************************************************************************)

type _ck_function_list

type ck_function_list = _ck_function_list structure

let ck_function_list : ck_function_list typ = structure "CK_FUNCTION_LIST"

module CK_NOTIFY : sig
  type u

  type t = u ptr

  val u : u typ

  val t : u ptr typ
end = struct
  type u = unit

  type t = u Ctypes.ptr

  let u = void

  let t = Ctypes.typedef (ptr void) "CK_NOTIFY"
end

module CK = struct
  let notify = CK_NOTIFY.t

  let session_info = ulong

  (** This module contains the type declarations for the API functions.  *)
  module TF (F : sig
    (** Subinterface of Ctypes.FOREIGN *)
    type 'a fn

    type 'a return

    val ( @-> ) : 'a Ctypes.typ -> 'b fn -> ('a -> 'b) fn

    val returning : 'a Ctypes.typ -> 'a return fn
  end) =
  struct
    open F

    let c_Initialize =
      (* ptr_opt InitializeArg.t @-> returning ck_rv *)
      ptr void @-> returning ck_rv

    let c_Finalize = ptr void @-> returning ck_rv

    let c_GetInfo = ptr ck_info @-> returning ck_rv

    let c_GetFunctionList = ptr (ptr ck_function_list) @-> returning ck_rv

    let c_GetSlotList =
      ck_bbool @-> ptr ck_slot_id @-> ptr ulong @-> returning ck_rv

    let c_GetSlotInfo = ck_slot_id @-> ptr ck_slot_info @-> returning ck_rv

    let c_GetTokenInfo = ck_slot_id @-> ptr ck_token_info @-> returning ck_rv

    let c_GetMechanismList =
      ck_slot_id @-> ptr ck_mechanism_type @-> ptr ulong @-> returning ck_rv

    let c_GetMechanismInfo =
      ck_slot_id
      @-> ck_mechanism_type
      @-> ptr ck_mechanism_info
      @-> returning ck_rv

    let c_InitToken =
      ck_slot_id @-> ptr utf8char @-> ulong @-> ptr utf8char @-> returning ck_rv

    let c_InitPIN =
      ck_session_handle @-> ptr utf8char @-> ulong @-> returning ck_rv

    let c_SetPIN =
      ck_session_handle
      @-> ptr utf8char
      @-> ulong
      @-> ptr utf8char
      @-> ulong
      @-> returning ck_rv

    let c_OpenSession =
      ck_slot_id
      @-> ck_flags
      @-> ptr void
      @-> notify
      @-> ptr ck_session_handle
      @-> returning ck_rv

    let c_CloseSession = ck_session_handle @-> returning ck_rv

    let c_CloseAllSessions = ck_slot_id @-> returning ck_rv

    let c_GetSessionInfo =
      ck_session_handle @-> ptr ck_session_info @-> returning ck_rv

    let c_GetOperationState =
      ck_session_handle @-> ptr ck_byte @-> ptr ulong @-> returning ck_rv

    let c_SetOperationState =
      ck_session_handle
      @-> ptr ck_byte
      @-> ulong
      @-> ck_object_handle
      @-> ck_object_handle
      @-> returning ck_rv

    let c_Login =
      ck_session_handle
      @-> ck_user_type
      @-> ptr utf8char
      @-> ulong
      @-> returning ck_rv

    let c_Logout = ck_session_handle @-> returning ck_rv

    let c_CreateObject =
      ck_session_handle
      @-> ptr ck_attribute
      @-> ulong
      @-> ptr ck_object_handle
      @-> returning ck_rv

    let c_CopyObject =
      ck_session_handle
      @-> ck_object_handle
      @-> ptr ck_attribute
      @-> ulong
      @-> ptr ck_object_handle
      @-> returning ck_rv

    let c_DestroyObject =
      ck_session_handle @-> ck_object_handle @-> returning ck_rv

    let c_GetObjectSize =
      ck_session_handle @-> ck_object_handle @-> ptr ulong @-> returning ck_rv

    let c_GetAttributeValue =
      ck_session_handle
      @-> ck_object_handle
      @-> ptr ck_attribute
      @-> ulong
      @-> returning ck_rv

    let c_SetAttributeValue =
      ck_session_handle
      @-> ck_object_handle
      @-> ptr ck_attribute
      @-> ulong
      @-> returning ck_rv

    (* Find object *)

    let c_FindObjectsInit =
      ck_session_handle @-> ptr ck_attribute @-> ulong @-> returning ck_rv

    let c_FindObjects =
      ck_session_handle
      @-> ptr ck_object_handle
      @-> ulong
      @-> ptr ulong
      @-> returning ck_rv

    let c_FindObjectsFinal = ck_session_handle @-> returning ck_rv

    (**************************************************************************)
    (*                          Encryption/decryption                         *)
    (**************************************************************************)

    let c_EncryptInit =
      ck_session_handle
      @-> ptr ck_mechanism
      @-> ck_object_handle
      @-> returning ck_rv

    let c_Encrypt =
      ck_session_handle
      @-> ptr ck_byte
      @-> ulong
      @-> ptr ck_byte
      @-> ptr ulong
      @-> returning ck_rv

    let c_EncryptUpdate =
      ck_session_handle
      @-> ptr ck_byte
      @-> ulong
      @-> ptr ck_byte
      @-> ptr ulong
      @-> returning ck_rv

    let c_EncryptFinal =
      ck_session_handle @-> ptr ck_byte @-> ptr ulong @-> returning ck_rv

    let c_DecryptInit =
      ck_session_handle
      @-> ptr ck_mechanism
      @-> ck_object_handle
      @-> returning ck_rv

    let c_Decrypt =
      ck_session_handle
      @-> ptr ck_byte
      @-> ulong
      @-> ptr ck_byte
      @-> ptr ulong
      @-> returning ck_rv

    let c_DecryptUpdate =
      ck_session_handle
      @-> ptr ck_byte
      @-> ulong
      @-> ptr ck_byte
      @-> ptr ulong
      @-> returning ck_rv

    let c_DecryptFinal =
      ck_session_handle @-> ptr ck_byte @-> ptr ulong @-> returning ck_rv

    (**************************************************************************)
    (*                            Message digesting                           *)
    (**************************************************************************)

    let c_DigestInit =
      ck_session_handle @-> ptr ck_mechanism @-> returning ck_rv

    let c_Digest =
      ck_session_handle
      @-> ptr ck_byte
      @-> ulong
      @-> ptr ck_byte
      @-> ptr ulong
      @-> returning ck_rv

    let c_DigestUpdate =
      ck_session_handle @-> ptr ck_byte @-> ulong @-> returning ck_rv

    let c_DigestKey = ck_session_handle @-> ck_object_handle @-> returning ck_rv

    let c_DigestFinal =
      ck_session_handle @-> ptr ck_byte @-> ptr ulong @-> returning ck_rv

    let c_SignInit =
      ck_session_handle
      @-> ptr ck_mechanism
      @-> ck_object_handle
      @-> returning ck_rv

    let c_Sign =
      ck_session_handle
      @-> ptr ck_byte
      @-> ulong
      @-> ptr ck_byte
      @-> ptr ulong
      @-> returning ck_rv

    let c_SignUpdate =
      ck_session_handle @-> ptr ck_byte @-> ulong @-> returning ck_rv

    let c_SignFinal =
      ck_session_handle @-> ptr ck_byte @-> ptr ulong @-> returning ck_rv

    let c_SignRecoverInit =
      ck_session_handle
      @-> ptr ck_mechanism
      @-> ck_object_handle
      @-> returning ck_rv

    let c_SignRecover =
      ck_session_handle
      @-> ptr ck_byte
      @-> ulong
      @-> ptr ck_byte
      @-> ptr ulong
      @-> returning ck_rv

    let c_VerifyInit =
      ck_session_handle
      @-> ptr ck_mechanism
      @-> ck_object_handle
      @-> returning ck_rv

    let c_Verify =
      ck_session_handle
      @-> ptr ck_byte
      @-> ulong
      @-> ptr ck_byte
      @-> ulong
      @-> returning ck_rv

    let c_VerifyUpdate =
      ck_session_handle @-> ptr ck_byte @-> ulong @-> returning ck_rv

    let c_VerifyFinal =
      ck_session_handle @-> ptr ck_byte @-> ulong @-> returning ck_rv

    let c_VerifyRecoverInit =
      ck_session_handle
      @-> ptr ck_mechanism
      @-> ck_object_handle
      @-> returning ck_rv

    let c_VerifyRecover =
      ck_session_handle
      @-> ptr ck_byte
      @-> ulong
      @-> ptr ck_byte
      @-> ptr ulong
      @-> returning ck_rv

    let c_DigestEncryptUpdate =
      ck_session_handle
      @-> ptr ck_byte
      @-> ulong
      @-> ptr ck_byte
      @-> ptr ulong
      @-> returning ck_rv

    let c_DecryptDigestUpdate =
      ck_session_handle
      @-> ptr ck_byte
      @-> ulong
      @-> ptr ck_byte
      @-> ptr ulong
      @-> returning ck_rv

    let c_SignEncryptUpdate =
      ck_session_handle
      @-> ptr ck_byte
      @-> ulong
      @-> ptr ck_byte
      @-> ptr ulong
      @-> returning ck_rv

    let c_DecryptVerifyUpdate =
      ck_session_handle
      @-> ptr ck_byte
      @-> ulong
      @-> ptr ck_byte
      @-> ptr ulong
      @-> returning ck_rv

    let c_GenerateKey =
      ck_session_handle
      @-> ptr ck_mechanism
      @-> ptr ck_attribute
      @-> ulong
      @-> ptr ck_object_handle
      @-> returning ck_rv

    let c_GenerateKeyPair =
      ck_session_handle
      @-> ptr ck_mechanism
      @-> ptr ck_attribute (* template for public key *)
      @-> ulong (* # elements for public key  template*)
      @-> ptr ck_attribute (* template for private key *)
      @-> ulong (* # elements for private key template *)
      @-> ptr ck_object_handle (* gets pub. key handle *)
      @-> ptr ck_object_handle (* gets priv. key handle *)
      @-> returning ck_rv

    let c_WrapKey =
      ck_session_handle
      @-> ptr ck_mechanism
      @-> ck_object_handle (* wrapping key *)
      @-> ck_object_handle (* key to be wrapped *)
      @-> ptr ck_byte (* gets wrapped key *)
      @-> ptr ulong (* gets wrapped key size *)
      @-> returning ck_rv

    let c_UnwrapKey =
      ck_session_handle
      @-> ptr ck_mechanism
      @-> ck_object_handle (* unwrapping key *)
      @-> ptr ck_byte (* wrapped key *)
      @-> ulong (* the wrapped key length *)
      @-> ptr ck_attribute (* new key template *)
      @-> ulong (* template length *)
      @-> ptr ck_object_handle (* gets new handle *)
      @-> returning ck_rv

    let c_DeriveKey =
      ck_session_handle (* session handle *)
      @-> ptr ck_mechanism (* key deriv. mechanism *)
      @-> ck_object_handle (* base key *)
      @-> ptr ck_attribute (* new key template *)
      @-> ulong (* template length *)
      @-> ptr ck_object_handle (* gets new handle *)
      @-> returning ck_rv

    let c_SeedRandom =
      ck_session_handle @-> ptr ck_byte @-> ulong @-> returning ck_rv

    let c_GenerateRandom =
      ck_session_handle @-> ptr ck_byte @-> ulong @-> returning ck_rv

    let c_GetFunctionStatus = ck_session_handle @-> returning ck_rv

    let c_CancelFunction = ck_session_handle @-> returning ck_rv

    let c_WaitForSlotEvent =
      ck_flags @-> ptr ck_slot_id @-> ptr void @-> returning ck_rv
  end

  module T = TF (struct
    type 'a fn = 'a Ctypes.fn

    type 'a return = 'a

    let ( @-> ) = Ctypes.( @-> )

    let returning = Ctypes.returning
  end)

  module Function_list = struct
    type t = (_ck_function_list, [`Struct]) Ctypes.structured

    let ( -: ) ty label =
      Ctypes_helpers.smart_field ck_function_list label (Foreign.funptr ty)

    let version =
      Ctypes_helpers.smart_field ck_function_list "version" ck_version

    let c_Initialize = T.c_Initialize -: "C_Initialize"

    let c_Finalize = T.c_Finalize -: "C_Finalize"

    let c_GetInfo = T.c_GetInfo -: "C_GetInfo"

    let c_GetFunction_list = T.c_GetFunctionList -: "C_GetFunctionList"

    let c_GetSlotList = T.c_GetSlotList -: "C_GetSlotList"

    let c_GetSlotInfo = T.c_GetSlotInfo -: "C_GetSlotInfo"

    let c_GetTokenInfo = T.c_GetTokenInfo -: "C_GetTokenInfo"

    let c_GetMechanismList = T.c_GetMechanismList -: "C_GetMechanismList"

    let c_GetMechanismInfo = T.c_GetMechanismInfo -: "C_GetMechanismInfo"

    let c_InitToken = T.c_InitToken -: "C_InitToken"

    let c_InitPIN = T.c_InitPIN -: "C_InitPIN"

    let c_SetPIN = T.c_SetPIN -: "C_SetPIN"

    let c_OpenSession = T.c_OpenSession -: "C_OpenSession"

    let c_CloseSession = T.c_CloseSession -: "C_CloseSession"

    let c_CloseAllSessions = T.c_CloseAllSessions -: "C_CloseAllSessions"

    let c_GetSessionInfo = T.c_GetSessionInfo -: "C_GetSessionInfo"

    let c_GetOperationState = T.c_GetOperationState -: "C_GetOperationState"

    let c_SetOperationState = T.c_SetOperationState -: "C_SetOperationState"

    let c_Login = T.c_Login -: "C_Login"

    let c_Logout = T.c_Logout -: "C_Logout"

    let c_CreateObject = T.c_CreateObject -: "C_CreateObject"

    let c_CopyObject = T.c_CopyObject -: "C_CopyObject"

    let c_DestroyObject = T.c_DestroyObject -: "C_DestroyObject"

    let c_GetObjectSize = T.c_GetObjectSize -: "C_GetObjectSize"

    let c_GetAttributeValue = T.c_GetAttributeValue -: "C_GetAttributeValue"

    let c_SetAttributeValue = T.c_SetAttributeValue -: "C_SetAttributeValue"

    let c_FindObjectsInit = T.c_FindObjectsInit -: "C_FindObjectsInit"

    let c_FindObjects = T.c_FindObjects -: "C_FindObjects"

    let c_FindObjectsFinal = T.c_FindObjectsFinal -: "C_FindObjectsFinal"

    let c_EncryptInit = T.c_EncryptInit -: "C_EncryptInit"

    let c_Encrypt = T.c_Encrypt -: "C_Encrypt"

    let c_EncryptUpdate = T.c_EncryptUpdate -: "C_EncryptUpdate"

    let c_EncryptFinal = T.c_EncryptFinal -: "C_EncryptFinal"

    let c_DecryptInit = T.c_DecryptInit -: "C_DecryptInit"

    let c_Decrypt = T.c_Decrypt -: "C_Decrypt"

    let c_DecryptUpdate = T.c_DecryptUpdate -: "C_DecryptUpdate"

    let c_DecryptFinal = T.c_DecryptFinal -: "C_DecryptFinal"

    let c_DigestInit = T.c_DigestInit -: "C_DigestInit"

    let c_Digest = T.c_Digest -: "C_Digest"

    let c_DigestUpdate = T.c_DigestUpdate -: "C_DigestUpdate"

    let c_DigestKey = T.c_DigestKey -: "C_DigestKey"

    let c_DigestFinal = T.c_DigestFinal -: "C_DigestFinal"

    let c_SignInit = T.c_SignInit -: "C_SignInit"

    let c_Sign = T.c_Sign -: "C_Sign"

    let c_SignUpdate = T.c_SignUpdate -: "C_SignUpdate"

    let c_SignFinal = T.c_SignFinal -: "C_SignFinal"

    let c_SignRecoverInit = T.c_SignRecoverInit -: "C_SignRecoverInit"

    let c_SignRecover = T.c_SignRecover -: "C_SignRecover"

    let c_VerifyInit = T.c_VerifyInit -: "C_VerifyInit"

    let c_Verify = T.c_Verify -: "C_Verify"

    let c_VerifyUpdate = T.c_VerifyUpdate -: "C_VerifyUpdate"

    let c_VerifyFinal = T.c_VerifyFinal -: "C_VerifyFinal"

    let c_VerifyRecoverInit = T.c_VerifyRecoverInit -: "C_VerifyRecoverInit"

    let c_VerifyRecover = T.c_VerifyRecover -: "C_VerifyRecover"

    let c_DigestEncryptUpdate =
      T.c_DigestEncryptUpdate -: "C_DigestEncryptUpdate"

    let c_DecryptDigestUpdate =
      T.c_DecryptDigestUpdate -: "C_DecryptDigestUpdate"

    let c_SignEncryptUpdate = T.c_SignEncryptUpdate -: "C_SignEncryptUpdate"

    let c_DecryptVerifyUpdate =
      T.c_DecryptVerifyUpdate -: "C_DecryptVerifyUpdate"

    let c_GenerateKey = T.c_GenerateKey -: "C_GenerateKey"

    let c_GenerateKeyPair = T.c_GenerateKeyPair -: "C_GenerateKeyPair"

    let c_WrapKey = T.c_WrapKey -: "C_WrapKey"

    let c_UnwrapKey = T.c_UnwrapKey -: "C_UnwrapKey"

    let c_DeriveKey = T.c_DeriveKey -: "C_DeriveKey"

    let c_SeedRandom = T.c_SeedRandom -: "C_SeedRandom"

    let c_GenerateRandom = T.c_GenerateRandom -: "C_GenerateRandom"

    let c_GetFunctionStatus = T.c_GetFunctionStatus -: "C_GetFunctionStatus"

    let c_CancelFunction = T.c_CancelFunction -: "C_CancelFunction"

    let c_WaitForSlotEvent = T.c_WaitForSlotEvent -: "C_WaitForSlotEvent"

    let () = seal ck_function_list
  end
end

module CK_FUNCTION_LIST = struct
  type t = ck_function_list
end
