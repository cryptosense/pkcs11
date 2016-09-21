open Ctypes
open Ctypes_helpers
open Pkcs11_helpers

type _t
type t = _t structure

let ck_info : t typ = structure "CK_INFO"

let (-:) ty label = smart_field ck_info label ty

let cryptoki_version = Pkcs11_CK_VERSION.ck_version -: "cryptokiVersion"
let manufacturer_id = array 32 char -: "manufacturerID"
let flags = ulong -: "flags"
let library_description = array 32 char -: "libraryDescription"
let library_version = Pkcs11_CK_VERSION.ck_version -: "libraryVersion"
let () = seal ck_info

(* User space *)
type u = {
  cryptokiVersion: Pkcs11_CK_VERSION.u;
  manufacturerID : string;
  flags : Pkcs11_CK_FLAGS.t;
  libraryDescription: string;
  libraryVersion : Pkcs11_CK_VERSION.u;
}

let view (c: t) : u =
  {
    cryptokiVersion =
      Pkcs11_CK_VERSION.view (getf c cryptoki_version);

    manufacturerID  =
      string_from_carray (getf c manufacturer_id);

    flags           =
      getf c flags;

    libraryDescription =
      string_from_carray (getf c library_description);

    libraryVersion  =
      Pkcs11_CK_VERSION.view (getf c library_version);
  }

let make (u : u) : t =
  let t = Ctypes.make ck_info in
  setf t cryptoki_version (Pkcs11_CK_VERSION.make u.cryptokiVersion);
  setf t manufacturer_id (carray_from_string (blank_padded ~length:32 u.manufacturerID));
  setf t flags u.flags;
  setf t library_description
    (carray_from_string (blank_padded ~length:32 u.libraryDescription));
  setf t library_version (Pkcs11_CK_VERSION.make u.libraryVersion);
  t

let string_of_flags = Pkcs11_CK_FLAGS.(to_pretty_string Info_domain)

let to_strings info =
  [
    "Version", Pkcs11_CK_VERSION.to_string info.cryptokiVersion;
    "Manufacturer ID", trim_and_quote info.manufacturerID;
    "Flags", string_of_flags info.flags;
    "Library Description", trim_and_quote info.libraryDescription;
    "Library Version", Pkcs11_CK_VERSION.to_string info.libraryVersion;
  ]

let to_string ?newlines ?indent info =
  string_of_record ?newlines ?indent (to_strings info)

let to_strings info = to_strings info |> strings_of_record
