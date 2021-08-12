open Ctypes
include Ctypes_helpers

let format_val = Ctypes.format

(* Logging functions. There is a bit of boilerplate, here. The problem
   is that simple solutions lead to printing the name of the function
   once, before it is even called... Also, this code is going to be
   called in a tight loop, so it is best to keep it efficient. *)
let rec log : type a. Format.formatter -> footer:string -> a fn -> a -> a =
 fun fmt ~footer -> function
  | Ctypes_static.Returns _ -> assert false
  | Ctypes_static.Function (ty, Ctypes_static.Returns ty') ->
    fun f x ->
      Format.fprintf fmt "%a) %!" (format_val ty) x;
      let result = f x in
      Format.fprintf fmt "// -> %a%s%!" (format_val ty') result footer;
      result
  | Ctypes_static.Function (ty, fn) ->
    fun f x ->
      Format.fprintf fmt "%a, " (format_val ty) x;
      log fmt ~footer fn (f x)

let log :
    type a. Format.formatter -> header:string -> footer:string -> a fn -> a -> a
    =
 fun fmt ~header ~footer -> function
  | Ctypes_static.Returns _ -> assert false
  | Ctypes_static.Function (ty, Ctypes_static.Returns ty') ->
    fun f x ->
      Format.fprintf fmt "%s (" header;
      Format.fprintf fmt "%a) %!" (format_val ty) x;
      let result = f x in
      Format.fprintf fmt "// -> %a%s%!" (format_val ty') result footer;
      result
  | Ctypes_static.Function (ty, fn) ->
    fun f x ->
      Format.fprintf fmt "%s (" header;
      Format.fprintf fmt "%a, " (format_val ty) x;
      log fmt ~footer fn (f x)

include Pkcs11_types
(******************************************************************************)
(*                                Raw signature                               *)
(******************************************************************************)

(** This module signature is used to ensure that both the direct style
    bindings and the indirect style bindings have the same interface. *)
module type LOW_LEVEL_BINDINGS = sig
  val c_GetFunctionList : CK_FUNCTION_LIST.t ptr ptr -> CK_RV.t

  val c_Initialize : CK_VOID.t ptr -> CK_RV.t

  val c_Finalize : CK_VOID.t ptr -> CK_RV.t

  val c_GetInfo : CK_INFO.t ptr -> CK_RV.t

  val c_GetTokenInfo : CK_SLOT_ID.t -> CK_TOKEN_INFO.t ptr -> CK_RV.t

  val c_GetSlotList : CK_BYTE.t -> CK_SLOT_ID.t ptr -> CK_ULONG.t ptr -> CK_RV.t

  val c_GetSlotInfo : CK_SLOT_ID.t -> CK_SLOT_INFO.t ptr -> CK_RV.t

  val c_GetMechanismList :
    CK_SLOT_ID.t -> CK_MECHANISM_TYPE.t ptr -> CK_ULONG.t ptr -> CK_RV.t

  val c_GetMechanismInfo :
    CK_SLOT_ID.t -> CK_MECHANISM_TYPE.t -> CK_MECHANISM_INFO.t ptr -> CK_RV.t

  val c_InitToken :
       CK_SLOT_ID.t
    -> CK_UTF8CHAR.t ptr
    -> CK_ULONG.t
    -> CK_UTF8CHAR.t ptr
    -> CK_RV.t

  val c_InitPIN :
    CK_SESSION_HANDLE.t -> CK_UTF8CHAR.t ptr -> CK_ULONG.t -> CK_RV.t

  val c_SetPIN :
       CK_SESSION_HANDLE.t
    -> CK_UTF8CHAR.t ptr
    -> CK_ULONG.t
    -> CK_UTF8CHAR.t ptr
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
    -> CK_UTF8CHAR.t ptr
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

(******************************************************************************)
(*                           Bindings maker                                   *)
(******************************************************************************)

(** Given a method to get the function list from the HSM and a function to extract function
    pointers from a retrieved function list, generate a full set of low-level bindings. *)
module Make_bindings (D : sig
  val declare :
       string
    -> ('a -> 'b, (_ck_function_list, [`Struct]) Ctypes.structured) Ctypes.field
    -> ('a -> 'b) Ctypes.fn
    -> 'a
    -> 'b

  val c_GetFunctionList : CK_FUNCTION_LIST.t ptr ptr -> CK_RV.t
end) : LOW_LEVEL_BINDINGS = struct
  open D
  module S = CK.Function_list

  let c_GetFunctionList = D.c_GetFunctionList

  let c_Initialize = declare "C_Initialize" S.c_Initialize CK.T.c_Initialize

  let c_Finalize = declare "C_Finalize" S.c_Finalize CK.T.c_Finalize

  let c_GetInfo = declare "C_GetInfo" S.c_GetInfo CK.T.c_GetInfo

  let c_GetTokenInfo =
    declare "C_GetTokenInfo" S.c_GetTokenInfo CK.T.c_GetTokenInfo

  let c_GetSlotList = declare "C_GetSlotList" S.c_GetSlotList CK.T.c_GetSlotList

  let c_GetSlotInfo = declare "C_GetSlotInfo" S.c_GetSlotInfo CK.T.c_GetSlotInfo

  let c_GetMechanismList =
    declare "C_GetMechanismList" S.c_GetMechanismList CK.T.c_GetMechanismList

  let c_GetMechanismInfo =
    declare "C_GetMechanismInfo" S.c_GetMechanismInfo CK.T.c_GetMechanismInfo

  let c_InitToken = declare "C_InitToken" S.c_InitToken CK.T.c_InitToken

  let c_InitPIN = declare "C_InitPIN" S.c_InitPIN CK.T.c_InitPIN

  let c_SetPIN = declare "C_SetPIN" S.c_SetPIN CK.T.c_SetPIN

  (******************************************************************************)
  (*                             Session Management                             *)
  (******************************************************************************)

  let c_OpenSession = declare "C_OpenSession" S.c_OpenSession CK.T.c_OpenSession

  let c_CloseSession =
    declare "C_CloseSession" S.c_CloseSession CK.T.c_CloseSession

  let c_CloseAllSessions =
    declare "C_CloseAllSessions" S.c_CloseAllSessions CK.T.c_CloseAllSessions

  let c_GetSessionInfo =
    declare "C_GetSessionInfo" S.c_GetSessionInfo CK.T.c_GetSessionInfo

  let c_GetOperationState =
    declare "C_GetOperationState" S.c_GetOperationState CK.T.c_GetOperationState

  let c_SetOperationState =
    declare "C_SetOperationState" S.c_SetOperationState CK.T.c_SetOperationState

  let c_Login = declare "C_Login" S.c_Login CK.T.c_Login

  let c_Logout = declare "C_Logout" S.c_Logout CK.T.c_Logout

  (******************************************************************************)
  (*                                Object Management                           *)
  (******************************************************************************)

  let c_CreateObject =
    declare "C_CreateObject" S.c_CreateObject CK.T.c_CreateObject

  let c_CopyObject = declare "C_CopyObject" S.c_CopyObject CK.T.c_CopyObject

  let c_DestroyObject =
    declare "C_DestroyObject" S.c_DestroyObject CK.T.c_DestroyObject

  let c_GetObjectSize =
    declare "C_GetObjectSize" S.c_GetObjectSize CK.T.c_GetObjectSize

  let c_GetAttributeValue =
    declare "C_GetAttributeValue" S.c_GetAttributeValue CK.T.c_GetAttributeValue

  let c_SetAttributeValue =
    declare "C_SetAttributeValue" S.c_SetAttributeValue CK.T.c_SetAttributeValue

  let c_FindObjectsInit =
    declare "C_FindObjectsInit" S.c_FindObjectsInit CK.T.c_FindObjectsInit

  let c_FindObjects = declare "C_FindObjects" S.c_FindObjects CK.T.c_FindObjects

  let c_FindObjectsFinal =
    declare "C_FindObjectsFinal" S.c_FindObjectsFinal CK.T.c_FindObjectsFinal

  (******************************************************************************)
  (*                          Encryption and decryption                         *)
  (******************************************************************************)

  let c_EncryptInit = declare "C_EncryptInit" S.c_EncryptInit CK.T.c_EncryptInit

  let c_Encrypt = declare "C_Encrypt" S.c_Encrypt CK.T.c_Encrypt

  let c_EncryptUpdate =
    declare "C_EncryptUpdate" S.c_EncryptUpdate CK.T.c_EncryptUpdate

  let c_EncryptFinal =
    declare "C_EncryptFinal" S.c_EncryptFinal CK.T.c_EncryptFinal

  let c_DecryptInit = declare "C_DecryptInit" S.c_DecryptInit CK.T.c_DecryptInit

  let c_Decrypt = declare "C_Decrypt" S.c_Decrypt CK.T.c_Decrypt

  let c_DecryptUpdate =
    declare "C_DecryptUpdate" S.c_DecryptUpdate CK.T.c_DecryptUpdate

  let c_DecryptFinal =
    declare "C_DecryptFinal" S.c_DecryptFinal CK.T.c_DecryptFinal

  (******************************************************************************)
  (*                             Digest                                         *)
  (******************************************************************************)

  let c_DigestInit = declare "C_DigestInit" S.c_DigestInit CK.T.c_DigestInit

  let c_Digest = declare "C_Digest" S.c_Digest CK.T.c_Digest

  let c_DigestUpdate =
    declare "C_DigestUpdate" S.c_DigestUpdate CK.T.c_DigestUpdate

  let c_DigestKey = declare "C_DigestKey" S.c_DigestKey CK.T.c_DigestKey

  let c_DigestFinal = declare "C_DigestFinal" S.c_DigestFinal CK.T.c_DigestFinal

  (******************************************************************************)
  (*                             Signing and MACing                             *)
  (******************************************************************************)

  let c_SignInit = declare "C_SignInit" S.c_SignInit CK.T.c_SignInit

  let c_Sign = declare "C_Sign" S.c_Sign CK.T.c_Sign

  let c_SignUpdate = declare "C_SignUpdate" S.c_SignUpdate CK.T.c_SignUpdate

  let c_SignFinal = declare "C_SignFinal" S.c_SignFinal CK.T.c_SignFinal

  let c_SignRecoverInit =
    declare "C_SignRecoverInit" S.c_SignRecoverInit CK.T.c_SignRecoverInit

  let c_SignRecover = declare "C_SignRecover" S.c_SignRecover CK.T.c_SignRecover

  let c_VerifyInit = declare "C_VerifyInit" S.c_VerifyInit CK.T.c_VerifyInit

  let c_Verify = declare "C_Verify" S.c_Verify CK.T.c_Verify

  let c_VerifyUpdate =
    declare "C_VerifyUpdate" S.c_VerifyUpdate CK.T.c_VerifyUpdate

  let c_VerifyFinal = declare "C_VerifyFinal" S.c_VerifyFinal CK.T.c_VerifyFinal

  let c_VerifyRecoverInit =
    declare "C_VerifyRecoverInit" S.c_VerifyRecoverInit CK.T.c_VerifyRecoverInit

  let c_VerifyRecover =
    declare "C_VerifyRecover" S.c_VerifyRecover CK.T.c_VerifyRecover

  let c_DigestEncryptUpdate =
    declare "C_DigestEncryptUpdate" S.c_DigestEncryptUpdate
      CK.T.c_DigestEncryptUpdate

  let c_DecryptDigestUpdate =
    declare "C_DecryptDigestUpdate" S.c_DecryptDigestUpdate
      CK.T.c_DecryptDigestUpdate

  let c_SignEncryptUpdate =
    declare "C_SignEncryptUpdate" S.c_SignEncryptUpdate CK.T.c_SignEncryptUpdate

  let c_DecryptVerifyUpdate =
    declare "C_DecryptVerifyUpdate" S.c_DecryptVerifyUpdate
      CK.T.c_DecryptVerifyUpdate

  (******************************************************************************)
  (*                               Key management                               *)
  (******************************************************************************)

  let c_GenerateKey = declare "C_GenerateKey" S.c_GenerateKey CK.T.c_GenerateKey

  let c_GenerateKeyPair =
    declare "C_GenerateKeyPair" S.c_GenerateKeyPair CK.T.c_GenerateKeyPair

  let c_WrapKey = declare "C_WrapKey" S.c_WrapKey CK.T.c_WrapKey

  let c_UnwrapKey = declare "C_UnwrapKey" S.c_UnwrapKey CK.T.c_UnwrapKey

  let c_DeriveKey = declare "C_DeriveKey" S.c_DeriveKey CK.T.c_DeriveKey

  let c_SeedRandom = declare "C_SeedRandom" S.c_SeedRandom CK.T.c_SeedRandom

  let c_GenerateRandom =
    declare "C_GenerateRandom" S.c_GenerateRandom CK.T.c_GenerateRandom

  let c_GetFunctionStatus =
    declare "C_GetFunctionStatus" S.c_GetFunctionStatus CK.T.c_GetFunctionStatus

  let c_CancelFunction =
    declare "C_CancelFunction" S.c_CancelFunction CK.T.c_CancelFunction

  let c_WaitForSlotEvent =
    declare "C_WaitForSlotEvent" S.c_WaitForSlotEvent CK.T.c_WaitForSlotEvent
end

module type CONFIG = sig
  val log_calls : (string * Format.formatter) option

  val library : Dl.library
end

(******************************************************************************)
(*                            Direct style bindings                           *)
(******************************************************************************)

module Direct (X : CONFIG) : LOW_LEVEL_BINDINGS = struct
  let declare : 'a 'b. string -> ('a -> 'b) Ctypes.fn -> 'a -> 'b =
   fun name typ ->
    let f = Foreign.foreign ~from:X.library ~stub:true name typ in
    (* let f = time (timer name) typ f in *)
    match X.log_calls with
    | None -> f
    | Some (prefix, fmt) ->
      log fmt ~header:(prefix ^ ": " ^ name) ~footer:"\n" typ f

  let c_GetFunctionList = declare "C_GetFunctionList" CK.T.c_GetFunctionList

  include Make_bindings (struct
    let declare
        (name : string)
        (_field :
          ( 'a -> 'b
          , (_ck_function_list, [`Struct]) Ctypes.structured )
          Ctypes.field)
        (typ : ('a -> 'b) Ctypes.fn) =
      declare name typ

    let c_GetFunctionList = c_GetFunctionList
  end)
end

(******************************************************************************)
(*                (Direct/Indirect) auto style bindings                       *)
(******************************************************************************)

module Auto (X : CONFIG) : LOW_LEVEL_BINDINGS = struct
  let c_GetFunctionList =
    Foreign.foreign ~from:X.library ~stub:true "C_GetFunctionList"
      CK.T.c_GetFunctionList

  (* compute the function_list lazily *)
  let function_list =
    lazy
      (let c_GetFunctionList : unit -> CK_RV.t * ck_function_list =
        fun () ->
         (* WARNING: This code is duplicated in the Make module below.  *)
         let p = allocate_n ~count:1 (ptr ck_function_list) in
         let rv = c_GetFunctionList p in
         (rv, !@(!@p))
       in
       let (rv, fl) = c_GetFunctionList () in
       if rv = CK_RV._CKR_OK then
         fl
       else
         raise Not_found)

  let declare name field typ =
    let f =
      try
        (* try to fetch the function from the function_list structure *)
        (* pointer of the field *)
        let f_ptr : _ Ctypes.ptr =
          Ctypes.( @. ) (Lazy.force function_list) field
        in
        (* cast to pointer of void *)
        let cast_ptr = Ctypes.from_voidp (ptr void) (Ctypes.to_voidp f_ptr) in
        (* test if null *)
        if is_null !@cast_ptr then
          raise Not_found
        else
          getf (Lazy.force function_list) field
      with
      | Sys.Break as break -> raise break
      | _ ->
        (* fallback to direct mode *)
        Foreign.foreign ~from:X.library ~stub:true name typ
    in
    match X.log_calls with
    | None -> f
    | Some (prefix, fmt) ->
      log fmt ~header:(prefix ^ ": " ^ name) ~footer:"\n" typ f

  module Raw_argument = struct
    let declare
        (name : string)
        (field :
          ( 'a -> 'b
          , (_ck_function_list, [`Struct]) Ctypes.structured )
          Ctypes.field)
        (typ : ('a -> 'b) Ctypes.fn) =
      declare name field typ

    let c_GetFunctionList = c_GetFunctionList
  end

  include Make_bindings (Raw_argument)
end

(******************************************************************************)
(*                           Fake bindings                                    *)
(******************************************************************************)

module Fake (X : sig end) : LOW_LEVEL_BINDINGS = struct
  let return v =
    let rec return : type a. a fn -> a = function
      | Ctypes_static.Returns _ -> Obj.magic v
      | Ctypes_static.Function (_ty, fn) -> fun _x -> return fn
    in
    return

  let nimplem = CK_RV._CKR_FUNCTION_NOT_SUPPORTED

  let declare _field typ = return nimplem typ

  let c_GetFunctionList =
    declare CK.Function_list.c_GetFunction_list CK.T.c_GetFunctionList

  include Make_bindings (struct
    let declare
        (name : string)
        (_field :
          ( 'a -> 'b
          , (_ck_function_list, [`Struct]) Ctypes.structured )
          Ctypes.field)
        (typ : ('a -> 'b) Ctypes.fn) =
      declare name typ

    let c_GetFunctionList = c_GetFunctionList
  end)
end

(******************************************************************************)
(*                                   Wrapper                                  *)
(******************************************************************************)

module type LOW_LEVEL_WRAPPER = sig
  val c_Initialize : Nss_initialize_arg.t option -> CK_RV.t

  val c_Finalize : unit -> CK_RV.t

  val c_GetInfo : unit -> CK_RV.t * P11_info.t

  (* 03/24/2015: At the moment, we do not need to use GetFunctionList
     from the high level bindings. Since this function is quite
     complicated in terms of bindings, we should refrain from using
     it. *)
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

module Wrap_low_level_bindings (F : LOW_LEVEL_BINDINGS) : LOW_LEVEL_WRAPPER =
struct
  let gen_raw_string s =
    let n = String.length s in
    let ulong = n |> Unsigned.ULong.of_int in
    (ptr_from_string s, ulong)

  let c_Initialize : Nss_initialize_arg.t option -> CK_RV.t =
    let f = F.c_Initialize in
    fun args ->
      let args_ptr =
        match args with
        | Some a -> Ctypes.to_voidp (Ctypes.addr a)
        | None -> Ctypes.null
      in
      f args_ptr

  let c_Finalize : unit -> CK_RV.t =
    let f = F.c_Finalize in
    fun () -> f Ctypes.null

  let c_GetInfo : unit -> CK_RV.t * P11_info.t =
    let f = F.c_GetInfo in
    fun () ->
      let info = Ctypes.make ck_info in
      let rv = f (Ctypes.addr info) in
      (rv, CK_INFO.view info)

  let c_GetTokenInfo : slot:CK_SLOT_ID.t -> CK_RV.t * P11_token_info.t =
    let f = F.c_GetTokenInfo in
    fun ~slot ->
      let info = Ctypes.make ck_token_info in
      let rv = f slot (Ctypes.addr info) in
      (rv, CK_TOKEN_INFO.view info)

  (* WARNING: This code is duplicated in the Indirect module above.  *)
  (* let c_GetFunctionList: unit -> CK_RV.t * ck_function_list = *)
  (*   let f = F.c_GetFunctionList in *)
  (*   fun () -> *)
  (*     let p = allocate_n ~count:1 ((ptr ck_function_list)) in *)
  (*     let rv = f p in *)
  (*     rv, !@ (!@ p) *)

  let c_GetSlotList : bool -> Slot_list.t -> CK_RV.t =
    let f = F.c_GetSlotList in
    fun tokenPresent slot_list ->
      let tp =
        CK_BYTE.(
          if tokenPresent then
            one
          else
            zero)
      in
      f tp
        (Slot_list.get_content slot_list)
        (Slot_list.get_length_addr slot_list)

  let c_GetSlotInfo =
    let f = F.c_GetSlotInfo in
    fun ~slot ->
      let info = Ctypes.make ck_slot_info in
      let rv = f slot (Ctypes.addr info) in
      (rv, CK_SLOT_INFO.view info)

  let c_GetMechanismList : slot:CK_SLOT_ID.t -> Mechanism_list.t -> CK_RV.t =
    let f = F.c_GetMechanismList in
    fun ~slot mechanism_list ->
      f slot
        (Mechanism_list.get_content mechanism_list)
        (Mechanism_list.get_length_addr mechanism_list)

  let c_GetMechanismInfo =
    let f = F.c_GetMechanismInfo in
    fun ~slot mechanism_type ->
      let info = Ctypes.make ck_mechanism_info in
      let rv = f slot mechanism_type (Ctypes.addr info) in
      (rv, CK_MECHANISM_INFO.view info)

  let c_InitToken =
    let f = F.c_InitToken in
    fun ~slot ~pin ~label ->
      (* pin *)
      let (pin_addr, nPin) = gen_raw_string pin in
      (* label *)
      let label_addr = ptr_from_string (blank_padded ~length:32 label) in
      f slot pin_addr nPin label_addr

  let c_InitPIN =
    let f = F.c_InitPIN in
    fun hSession pin ->
      let (pin_addr, nPin) = gen_raw_string pin in
      f hSession pin_addr nPin

  let c_SetPIN =
    let f = F.c_SetPIN in
    fun hSession ~oldpin ~newpin ->
      let (oldPin_addr, nOldPin) = gen_raw_string oldpin in
      let (newPin_addr, nNewPin) = gen_raw_string newpin in
      f hSession oldPin_addr nOldPin newPin_addr nNewPin

  (******************************************************************************)
  (*                             Session Management                             *)
  (******************************************************************************)

  let c_OpenSession :
      slot:CK_SLOT_ID.t -> flags:CK_FLAGS.t -> CK_RV.t * CK_SESSION_HANDLE.t =
    let f = F.c_OpenSession in
    fun ~slot ~flags ->
      let hSession = Ctypes.allocate ck_session_handle Unsigned.ULong.zero in
      let rv =
        f slot flags Ctypes.null Ctypes.(from_voidp CK_NOTIFY.u null) hSession
      in
      (rv, Ctypes.(!@hSession))

  let c_CloseSession : CK_SESSION_HANDLE.t -> CK_RV.t =
    let f = F.c_CloseSession in
    fun hSession -> f hSession

  let c_CloseAllSessions : slot:CK_SLOT_ID.t -> CK_RV.t =
    let f = F.c_CloseAllSessions in
    fun ~slot -> f slot

  let c_GetSessionInfo : CK_SESSION_HANDLE.t -> CK_RV.t * P11_session_info.t =
    let f = F.c_GetSessionInfo in
    fun hSession ->
      let info = Ctypes.make ck_session_info in
      let rv = f hSession (Ctypes.addr info) in
      (rv, CK_SESSION_INFO.view info)

  let c_Login : CK_SESSION_HANDLE.t -> CK_USER_TYPE.t -> string -> CK_RV.t =
    let f = F.c_Login in
    fun hSession user pin ->
      let (pin_addr, nPin) = gen_raw_string pin in
      f hSession user pin_addr nPin

  let c_Logout : CK_SESSION_HANDLE.t -> CK_RV.t = F.c_Logout

  (******************************************************************************)
  (*                                Object Management                           *)
  (******************************************************************************)

  let c_CreateObject :
      CK_SESSION_HANDLE.t -> template -> CK_RV.t * CK_OBJECT_HANDLE.t =
    let f = F.c_CreateObject in
    fun hSession template ->
      let pTemplate = Ctypes.CArray.start template in
      let ulCount = Unsigned.ULong.of_int (Ctypes.CArray.length template) in
      let hObject = Ctypes.allocate ck_object_handle Unsigned.ULong.zero in
      let rv = f hSession pTemplate ulCount hObject in
      (rv, Ctypes.(!@hObject))

  let c_CopyObject :
         CK_SESSION_HANDLE.t
      -> CK_OBJECT_HANDLE.t
      -> template
      -> CK_RV.t * CK_OBJECT_HANDLE.t =
    let f = F.c_CopyObject in
    fun hSession hObject template ->
      let pTemplate = Ctypes.CArray.start template in
      let ulCount = Unsigned.ULong.of_int (Ctypes.CArray.length template) in
      let hObject' = Ctypes.allocate ck_object_handle Unsigned.ULong.zero in
      let rv = f hSession hObject pTemplate ulCount hObject' in
      (rv, Ctypes.(!@hObject'))

  let c_DestroyObject : CK_SESSION_HANDLE.t -> CK_OBJECT_HANDLE.t -> CK_RV.t =
    F.c_DestroyObject

  let c_GetAttributeValue :
      CK_SESSION_HANDLE.t -> CK_OBJECT_HANDLE.t -> template -> CK_RV.t =
    let f = F.c_GetAttributeValue in
    fun hSession hObject template ->
      let pTemplate = Ctypes.CArray.start template in
      let ulCount = Unsigned.ULong.of_int (Ctypes.CArray.length template) in
      f hSession hObject pTemplate ulCount

  let c_SetAttributeValue :
      CK_SESSION_HANDLE.t -> CK_OBJECT_HANDLE.t -> template -> CK_RV.t =
    let f = F.c_SetAttributeValue in
    fun hSession hObject template ->
      let pTemplate = Ctypes.CArray.start template in
      let ulCount = Unsigned.ULong.of_int (Ctypes.CArray.length template) in
      f hSession hObject pTemplate ulCount

  let c_FindObjectsInit : CK_SESSION_HANDLE.t -> template -> CK_RV.t =
    let f = F.c_FindObjectsInit in
    fun hSession template ->
      let pTemplate = Ctypes.CArray.start template in
      let ulCount = Unsigned.ULong.of_int (Ctypes.CArray.length template) in
      f hSession pTemplate ulCount

  let c_FindObjects :
      CK_SESSION_HANDLE.t -> max_size:int -> CK_RV.t * CK_OBJECT_HANDLE.t list =
    let f = F.c_FindObjects in
    fun hSession ~max_size ->
      let ulMaxObjectCount = Unsigned.ULong.of_int max_size in
      let phObject = Ctypes.allocate_n ck_object_handle ~count:max_size in
      let pulObjectCount = Ctypes.(allocate ulong (Unsigned.ULong.of_int 0)) in
      let rv = f hSession phObject ulMaxObjectCount pulObjectCount in
      let objectCount = Unsigned.ULong.to_int !@pulObjectCount in
      let objects = Ctypes.CArray.(from_ptr phObject objectCount |> to_list) in
      (rv, objects)

  let c_FindObjectsFinal : CK_SESSION_HANDLE.t -> CK_RV.t = F.c_FindObjectsFinal

  (******************************************************************************)
  (*                          Encryption and decryption                         *)
  (******************************************************************************)

  let c_EncryptInit :
      CK_SESSION_HANDLE.t -> CK_MECHANISM.t -> CK_OBJECT_HANDLE.t -> CK_RV.t =
    let f = F.c_EncryptInit in
    fun hSession mechanism hObject ->
      let pMechanism = Ctypes.addr mechanism in
      f hSession pMechanism hObject

  (* Modifies the [~tgt] argument in place. *)
  let c_Encrypt : CK_SESSION_HANDLE.t -> src:Data.t -> tgt:Data.t -> CK_RV.t =
    let f = F.c_Encrypt in
    fun hSession ~src ~tgt ->
      f hSession (Data.get_content src) (Data.get_length src)
        (Data.get_content tgt) (Data.get_length_addr tgt)

  let c_EncryptUpdate : CK_SESSION_HANDLE.t -> Data.t -> Data.t -> CK_RV.t =
    let f = F.c_EncryptUpdate in
    fun hSession src tgt ->
      f hSession (Data.get_content src) (Data.get_length src)
        (Data.get_content tgt) (Data.get_length_addr tgt)

  let c_EncryptFinal : CK_SESSION_HANDLE.t -> Data.t -> CK_RV.t =
    let f = F.c_EncryptFinal in
    fun hSession tgt ->
      f hSession (Data.get_content tgt) (Data.get_length_addr tgt)

  let c_DecryptInit :
      CK_SESSION_HANDLE.t -> CK_MECHANISM.t -> CK_OBJECT_HANDLE.t -> CK_RV.t =
    let f = F.c_DecryptInit in
    fun hSession mechanism hObject ->
      let pMechanism = Ctypes.addr mechanism in
      f hSession pMechanism hObject

  (* Modifies the [~tgt] argument. *)
  let c_Decrypt : CK_SESSION_HANDLE.t -> src:Data.t -> tgt:Data.t -> CK_RV.t =
    let f = F.c_Decrypt in
    fun hSession ~src ~tgt ->
      f hSession (Data.get_content src) (Data.get_length src)
        (Data.get_content tgt) (Data.get_length_addr tgt)

  let c_DecryptUpdate : CK_SESSION_HANDLE.t -> Data.t -> Data.t -> CK_RV.t =
    let f = F.c_DecryptUpdate in
    fun hSession src tgt ->
      f hSession (Data.get_content src) (Data.get_length src)
        (Data.get_content tgt) (Data.get_length_addr tgt)

  let c_DecryptFinal : CK_SESSION_HANDLE.t -> Data.t -> CK_RV.t =
    let f = F.c_DecryptFinal in
    fun hSession tgt ->
      f hSession (Data.get_content tgt) (Data.get_length_addr tgt)

  (******************************************************************************)
  (*                             Message digesting                              *)
  (******************************************************************************)

  let c_DigestInit : CK_SESSION_HANDLE.t -> CK_MECHANISM.t -> CK_RV.t =
    let f = F.c_DigestInit in
    fun hSession mechanism ->
      let pMechanism = Ctypes.addr mechanism in
      f hSession pMechanism

  let c_Digest : CK_SESSION_HANDLE.t -> Data.t -> Data.t -> CK_RV.t =
    let f = F.c_Digest in
    fun hSession src tgt ->
      f hSession (Data.get_content src) (Data.get_length src)
        (Data.get_content tgt) (Data.get_length_addr tgt)

  let c_DigestUpdate : CK_SESSION_HANDLE.t -> Data.t -> CK_RV.t =
    let f = F.c_DigestUpdate in
    fun hSession src -> f hSession (Data.get_content src) (Data.get_length src)

  let c_DigestKey : CK_SESSION_HANDLE.t -> CK_OBJECT_HANDLE.t -> CK_RV.t =
    let f = F.c_DigestKey in
    fun hSession hObject -> f hSession hObject

  let c_DigestFinal : CK_SESSION_HANDLE.t -> Data.t -> CK_RV.t =
    let f = F.c_DigestFinal in
    fun hSession tgt ->
      f hSession (Data.get_content tgt) (Data.get_length_addr tgt)

  (******************************************************************************)
  (*                             Signing and MACing                             *)
  (******************************************************************************)

  let c_SignInit :
      CK_SESSION_HANDLE.t -> CK_MECHANISM.t -> CK_OBJECT_HANDLE.t -> CK_RV.t =
    let f = F.c_SignInit in
    fun hSession mechanism hObject ->
      let pMechanism = Ctypes.addr mechanism in
      f hSession pMechanism hObject

  let c_Sign : CK_SESSION_HANDLE.t -> src:Data.t -> tgt:Data.t -> CK_RV.t =
    let f = F.c_Sign in
    fun hSession ~src ~tgt ->
      f hSession (Data.get_content src) (Data.get_length src)
        (Data.get_content tgt) (Data.get_length_addr tgt)

  let c_SignUpdate : CK_SESSION_HANDLE.t -> Data.t -> CK_RV.t =
    let f = F.c_SignUpdate in
    fun hSession part ->
      f hSession (Data.get_content part) (Data.get_length part)

  let c_SignFinal : CK_SESSION_HANDLE.t -> Data.t -> CK_RV.t =
    let f = F.c_SignFinal in
    fun hSession signature ->
      f hSession (Data.get_content signature) (Data.get_length_addr signature)

  let c_SignRecoverInit :
      CK_SESSION_HANDLE.t -> CK_MECHANISM.t -> CK_OBJECT_HANDLE.t -> CK_RV.t =
    let f = F.c_SignRecoverInit in
    fun hSession mechanism hObject ->
      let pMechanism = Ctypes.addr mechanism in
      f hSession pMechanism hObject

  let c_SignRecover : CK_SESSION_HANDLE.t -> src:Data.t -> tgt:Data.t -> CK_RV.t
      =
    let f = F.c_SignRecover in
    fun hSession ~src ~tgt ->
      f hSession (Data.get_content src) (Data.get_length src)
        (Data.get_content tgt) (Data.get_length_addr tgt)

  let c_VerifyInit :
      CK_SESSION_HANDLE.t -> CK_MECHANISM.t -> CK_OBJECT_HANDLE.t -> CK_RV.t =
    let f = F.c_VerifyInit in
    fun hSession mechanism hObject ->
      let pMechanism = Ctypes.addr mechanism in
      f hSession pMechanism hObject

  let c_Verify :
      CK_SESSION_HANDLE.t -> signed:Data.t -> signature:Data.t -> CK_RV.t =
    let f = F.c_Verify in
    fun hSession ~signed ~signature ->
      f hSession (Data.get_content signed) (Data.get_length signed)
        (Data.get_content signature)
        (Data.get_length signature)

  let c_VerifyUpdate : CK_SESSION_HANDLE.t -> Data.t -> CK_RV.t =
    let f = F.c_VerifyUpdate in
    fun hSession part ->
      f hSession (Data.get_content part) (Data.get_length part)

  let c_VerifyFinal : CK_SESSION_HANDLE.t -> Data.t -> CK_RV.t =
    let f = F.c_VerifyFinal in
    fun hSession signature ->
      f hSession (Data.get_content signature) (Data.get_length signature)

  let c_VerifyRecoverInit :
      CK_SESSION_HANDLE.t -> CK_MECHANISM.t -> CK_OBJECT_HANDLE.t -> CK_RV.t =
    let f = F.c_VerifyRecoverInit in
    fun hSession mechanism hObject ->
      let pMechanism = Ctypes.addr mechanism in
      f hSession pMechanism hObject

  let c_VerifyRecover :
      CK_SESSION_HANDLE.t -> signature:Data.t -> signed:Data.t -> CK_RV.t =
    let f = F.c_VerifyRecover in
    fun hSession ~signature ~signed ->
      f hSession
        (Data.get_content signature)
        (Data.get_length signature)
        (Data.get_content signed)
        (Data.get_length_addr signed)

  (******************************************************************************)
  (*                   Dual-function cryptographic                              *)
  (******************************************************************************)

  let c_DigestEncryptUpdate :
      CK_SESSION_HANDLE.t -> src:Data.t -> tgt:Data.t -> CK_RV.t =
    let f = F.c_DigestEncryptUpdate in
    fun hSession ~src ~tgt ->
      f hSession (Data.get_content src) (Data.get_length src)
        (Data.get_content tgt) (Data.get_length_addr tgt)

  let c_DecryptDigestUpdate :
      CK_SESSION_HANDLE.t -> src:Data.t -> tgt:Data.t -> CK_RV.t =
    let f = F.c_DecryptDigestUpdate in
    fun hSession ~src ~tgt ->
      f hSession (Data.get_content src) (Data.get_length src)
        (Data.get_content tgt) (Data.get_length_addr tgt)

  let c_SignEncryptUpdate :
      CK_SESSION_HANDLE.t -> src:Data.t -> tgt:Data.t -> CK_RV.t =
    let f = F.c_SignEncryptUpdate in
    fun hSession ~src ~tgt ->
      f hSession (Data.get_content src) (Data.get_length src)
        (Data.get_content tgt) (Data.get_length_addr tgt)

  let c_DecryptVerifyUpdate :
      CK_SESSION_HANDLE.t -> src:Data.t -> tgt:Data.t -> CK_RV.t =
    let f = F.c_DecryptVerifyUpdate in
    fun hSession ~src ~tgt ->
      f hSession (Data.get_content src) (Data.get_length src)
        (Data.get_content tgt) (Data.get_length_addr tgt)

  (******************************************************************************)
  (*                               Key management                               *)
  (******************************************************************************)

  let c_GenerateKey :
         CK_SESSION_HANDLE.t
      -> CK_MECHANISM.t
      -> Template.t
      -> CK_RV.t * CK_OBJECT_HANDLE.t =
    let f = F.c_GenerateKey in
    fun hSession mechanism template ->
      let pMechanism = Ctypes.addr mechanism in
      let pTemplate = Ctypes.CArray.start template in
      let ulCount = Unsigned.ULong.of_int (Ctypes.CArray.length template) in
      let hObject = Ctypes.allocate ck_object_handle Unsigned.ULong.zero in
      let rv = f hSession pMechanism pTemplate ulCount hObject in
      (rv, Ctypes.(!@hObject))

  let c_GenerateKeyPair :
         CK_SESSION_HANDLE.t
      -> CK_MECHANISM.t
      -> public:Template.t
      -> privat:Template.t
      -> CK_RV.t * CK_OBJECT_HANDLE.t * CK_OBJECT_HANDLE.t =
    let f = F.c_GenerateKeyPair in
    fun hSession mechanism ~public ~privat ->
      let hPublic = Ctypes.allocate ck_object_handle Unsigned.ULong.zero in
      let hPrivat = Ctypes.allocate ck_object_handle Unsigned.ULong.zero in

      let pPublicTemplate = Ctypes.CArray.start public in
      let pPrivatTemplate = Ctypes.CArray.start privat in

      let lPublicTemplate =
        Ctypes.CArray.length public |> Unsigned.ULong.of_int
      in
      let lPrivatTemplate =
        Ctypes.CArray.length privat |> Unsigned.ULong.of_int
      in

      let rv =
        f hSession (Ctypes.addr mechanism) pPublicTemplate lPublicTemplate
          pPrivatTemplate lPrivatTemplate hPublic hPrivat
      in
      (rv, Ctypes.(!@hPublic), Ctypes.(!@hPrivat))

  let c_WrapKey :
         CK_SESSION_HANDLE.t
      -> CK_MECHANISM.t
      -> wrapping_key:CK_OBJECT_HANDLE.t
      -> key:CK_OBJECT_HANDLE.t
      -> wrapped_key:Data.t
      -> CK_RV.t =
    let f = F.c_WrapKey in
    fun hSession mechanism ~wrapping_key ~key ~wrapped_key ->
      f hSession (Ctypes.addr mechanism) wrapping_key key
        (Data.get_content wrapped_key)
        (Data.get_length_addr wrapped_key)

  let c_UnwrapKey :
         CK_SESSION_HANDLE.t
      -> CK_MECHANISM.t
      -> unwrapping_key:CK_OBJECT_HANDLE.t
      -> wrapped_key:Data.t
      -> Template.t
      -> CK_RV.t * CK_OBJECT_HANDLE.t =
    let f = F.c_UnwrapKey in
    fun hSession mechanism ~unwrapping_key ~wrapped_key template ->
      let pTemplate = Ctypes.CArray.start template in
      let lTemplate = Ctypes.CArray.length template |> Unsigned.ULong.of_int in
      let hObject = Ctypes.allocate ck_object_handle Unsigned.ULong.zero in
      let rv =
        f hSession (Ctypes.addr mechanism) unwrapping_key
          (Data.get_content wrapped_key)
          (Data.get_length wrapped_key)
          pTemplate lTemplate hObject
      in
      (rv, !@hObject)

  let c_DeriveKey :
         CK_SESSION_HANDLE.t
      -> CK_MECHANISM.t
      -> CK_OBJECT_HANDLE.t
      -> Template.t
      -> CK_RV.t * CK_OBJECT_HANDLE.t =
    let f = F.c_DeriveKey in
    fun hSession mechanism hObject template ->
      let pTemplate = Ctypes.CArray.start template in
      let lTemplate = Ctypes.CArray.length template |> Unsigned.ULong.of_int in
      let hObject' = Ctypes.allocate ck_object_handle Unsigned.ULong.zero in
      let rv =
        f hSession (Ctypes.addr mechanism) hObject pTemplate lTemplate hObject'
      in
      (rv, !@hObject')
end

let load_driver
    ?log_calls
    ?on_unknown
    ?(load_mode = P11.Load_mode.auto)
    filename =
  (match on_unknown with
  | Some f -> Pkcs11_log.set_logging_function f
  | None -> ());
  if filename = "" then
    (module Fake () : LOW_LEVEL_BINDINGS)
  else
    let module M : CONFIG = struct
      let log_calls = log_calls

      let library = Dl.dlopen ~filename ~flags:[Dl.RTLD_LAZY]
    end in
    match load_mode with
    | Auto -> (module Auto (M))
    | FFI -> (module Direct (M))
