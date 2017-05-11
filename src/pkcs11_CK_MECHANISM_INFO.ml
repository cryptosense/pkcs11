open Ctypes
open Pkcs11_helpers

type _t
type t = _t structure

let ck_mechanism_info : t typ = structure "CK_MECHANISM_INFO"
let (-:) ty label = Ctypes_helpers.smart_field ck_mechanism_info label ty

let ulMinKeySize = ulong -: "ulMinKeySize"
let ulMaxKeySize = ulong -: "ulMaxKeySize"
let flags = Pkcs11_CK_FLAGS.typ -: "flags"
let () = seal ck_mechanism_info

type u =
  {
    ulMinKeySize: Unsigned.ULong.t;
    ulMaxKeySize: Unsigned.ULong.t;
    flags: Pkcs11_CK_FLAGS.t;
  }


let view (c: t) : u =
  {
    ulMinKeySize = getf c ulMinKeySize;

    ulMaxKeySize = getf c ulMaxKeySize;

    flags        = getf c flags;
  }

let make (u:u) : t =
  let t = Ctypes.make ck_mechanism_info in
  setf t ulMinKeySize u.ulMinKeySize;
  setf t ulMaxKeySize u.ulMaxKeySize;
  setf t flags u.flags;
  t

let allowed_flags =
  let flags = P11_flags.(flags_of_domain Mechanism_info_domain) in
  let flags = List.map fst flags in
  List.fold_left P11_flags.logical_or Pkcs11_CK_FLAGS.empty flags

let string_of_flags = P11_flags.(to_pretty_string Mechanism_info_domain)
let strings_of_flags = P11_flags.(to_pretty_strings Mechanism_info_domain)

let to_strings info =
  [
    "Minimum Key Size", Unsigned.ULong.to_string info.ulMinKeySize;
    "Maximum Key Size", Unsigned.ULong.to_string info.ulMaxKeySize;
    "Flags", string_of_flags info.flags;
  ]

let to_string ?newlines ?indent info =
  string_of_record ?newlines ?indent (to_strings info)

let to_strings info = to_strings info |> strings_of_record
