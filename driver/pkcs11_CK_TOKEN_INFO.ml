open Ctypes
open Ctypes_helpers

type _t

type t = _t structure

let ck_token_info : t typ = structure "CK_TOKEN_INFO"

let ( -: ) ty label = smart_field ck_token_info label ty

let label = array 32 Pkcs11_CK_UTF8CHAR.typ -: "label" (* blank padded *)

let manufacturerID = array 32 Pkcs11_CK_UTF8CHAR.typ -: "manufacturerID"
(* blank padded *)

let model = array 16 Pkcs11_CK_UTF8CHAR.typ -: "model" (* blank padded *)

let serialNumber = array 16 char -: "serialNumber" (* blank padded *)

let flags = Pkcs11_CK_FLAGS.typ -: "flags"

let ulMaxSessionCount = ulong -: "ulMaxSessionCount" (* max open sessions *)

let ulSessionCount = ulong -: "ulSessionCount" (* sess. now open *)

let ulMaxRwSessionCount = ulong -: "ulMaxRwSessionCount" (* max R/W sessions *)

let ulRwSessionCount = ulong -: "ulRwSessionCount" (* R/W sess. now open *)

let ulMaxPinLen = ulong -: "ulMaxPinLen" (* in bytes *)

let ulMinPinLen = ulong -: "ulMinPinLen" (* in bytes *)

let ulTotalPublicMemory = ulong -: "ulTotalPublicMemory" (* in bytes *)

let ulFreePublicMemory = ulong -: "ulFreePublicMemory" (* in bytes *)

let ulTotalPrivateMemory = ulong -: "ulTotalPrivateMemory" (* in bytes *)

let ulFreePrivateMemory = ulong -: "ulFreePrivateMemory" (* in bytes *)

let hardwareVersion = Pkcs11_CK_VERSION.ck_version -: "hardwareVersion"
(* version of hardware *)

let firmwareVersion = Pkcs11_CK_VERSION.ck_version -: "firmwareVersion"
(* version of firmware *)

let utcTime = array 16 char -: "utcTime" (* time *)

let () = seal ck_token_info

let view c =
  let open P11_token_info in
  { label = string_from_carray (getf c label)
  ; manufacturerID = string_from_carray (getf c manufacturerID)
  ; model = string_from_carray (getf c model)
  ; serialNumber = string_from_carray (getf c serialNumber)
  ; flags = getf c flags
  ; ulMaxSessionCount = getf c ulMaxSessionCount
  ; ulSessionCount = getf c ulSessionCount
  ; ulMaxRwSessionCount = getf c ulMaxRwSessionCount
  ; ulRwSessionCount = getf c ulRwSessionCount
  ; ulMaxPinLen = getf c ulMaxPinLen
  ; ulMinPinLen = getf c ulMinPinLen
  ; ulTotalPublicMemory = getf c ulTotalPublicMemory
  ; ulFreePublicMemory = getf c ulFreePublicMemory
  ; ulTotalPrivateMemory = getf c ulTotalPrivateMemory
  ; ulFreePrivateMemory = getf c ulFreePrivateMemory
  ; hardwareVersion = Pkcs11_CK_VERSION.view (getf c hardwareVersion)
  ; firmwareVersion = Pkcs11_CK_VERSION.view (getf c firmwareVersion)
  ; utcTime = string_from_carray (getf c utcTime) }

let make u =
  let open P11_token_info in
  let t = Ctypes.make ck_token_info in
  setf t label (carray_from_string (blank_padded ~length:32 u.label));
  setf t manufacturerID
    (carray_from_string (blank_padded ~length:32 u.manufacturerID));
  setf t model (carray_from_string (blank_padded ~length:16 u.model));
  setf t serialNumber
    (carray_from_string (blank_padded ~length:16 u.serialNumber));
  setf t flags u.flags;
  setf t ulMaxSessionCount u.ulMaxSessionCount;
  setf t ulSessionCount u.ulSessionCount;
  setf t ulMaxRwSessionCount u.ulMaxRwSessionCount;
  setf t ulRwSessionCount u.ulRwSessionCount;
  setf t ulMaxPinLen u.ulMaxPinLen;
  setf t ulMinPinLen u.ulMinPinLen;
  setf t ulTotalPublicMemory u.ulTotalPublicMemory;
  setf t ulFreePublicMemory u.ulFreePublicMemory;
  setf t ulTotalPrivateMemory u.ulTotalPrivateMemory;
  setf t ulFreePrivateMemory u.ulFreePrivateMemory;
  setf t hardwareVersion (Pkcs11_CK_VERSION.make u.hardwareVersion);
  setf t firmwareVersion (Pkcs11_CK_VERSION.make u.firmwareVersion);
  setf t utcTime (carray_from_string (blank_padded ~length:16 u.utcTime));
  t
