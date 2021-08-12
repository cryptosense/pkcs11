open Ctypes
open Ctypes_helpers

type _t

type t = _t structure

let ck_info : t typ = structure "CK_INFO"

let ( -: ) ty label = smart_field ck_info label ty

let cryptoki_version = Pkcs11_CK_VERSION.ck_version -: "cryptokiVersion"

let manufacturer_id = array 32 char -: "manufacturerID"

let flags = ulong -: "flags"

let library_description = array 32 char -: "libraryDescription"

let library_version = Pkcs11_CK_VERSION.ck_version -: "libraryVersion"

let () = seal ck_info

let view c =
  let open P11_info in
  { cryptokiVersion = Pkcs11_CK_VERSION.view (getf c cryptoki_version)
  ; manufacturerID = string_from_carray (getf c manufacturer_id)
  ; flags = getf c flags
  ; libraryDescription = string_from_carray (getf c library_description)
  ; libraryVersion = Pkcs11_CK_VERSION.view (getf c library_version) }

let make u =
  let open P11_info in
  let t = Ctypes.make ck_info in
  setf t cryptoki_version (Pkcs11_CK_VERSION.make u.cryptokiVersion);
  setf t manufacturer_id
    (carray_from_string (blank_padded ~length:32 u.manufacturerID));
  setf t flags u.flags;
  setf t library_description
    (carray_from_string (blank_padded ~length:32 u.libraryDescription));
  setf t library_version (Pkcs11_CK_VERSION.make u.libraryVersion);
  t
