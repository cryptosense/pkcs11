open Ctypes

open Ctypes_helpers

type _t
type t = _t structure

let ck_slot_info : t typ = structure "CK_SLOT_INFO"
let (-:) ty label = smart_field ck_slot_info label ty

let slotDescription = array 64 Pkcs11_CK_UTF8CHAR.typ -: "slotDescription"
let manufacturerID = array 32 Pkcs11_CK_UTF8CHAR.typ  -: "manufacturerID"
let flags = Pkcs11_CK_FLAGS.typ -: "flags"
let hardwareVersion = Pkcs11_CK_VERSION.ck_version -: "hardwareVersion"
let firmwareVersion = Pkcs11_CK_VERSION.ck_version -: "firmwareVersion"
let () = seal ck_slot_info

type u =
  {
    slotDescription: string;
    manufacturerID : string;
    flags: Pkcs11_CK_ULONG.t;
    hardwareVersion: P11_version.t;
    firmwareVersion: P11_version.t;
  }

let view (c: t) : u =
  {
    slotDescription =
      string_from_carray (getf c slotDescription);

    manufacturerID       =
      string_from_carray (getf c manufacturerID);

    flags                =
      getf c flags;

    hardwareVersion      =
      Pkcs11_CK_VERSION.view (getf c hardwareVersion);

    firmwareVersion      =
      Pkcs11_CK_VERSION.view (getf c firmwareVersion);
  }

let make (u : u) : t =
  let t = Ctypes.make ck_slot_info in
  setf t slotDescription (carray_from_string (blank_padded ~length:64 u.slotDescription));
  setf t manufacturerID (carray_from_string (blank_padded ~length:32 u.manufacturerID));
  setf t flags (u.flags);
  setf t hardwareVersion (Pkcs11_CK_VERSION.make u.hardwareVersion);
  setf t firmwareVersion (Pkcs11_CK_VERSION.make u.firmwareVersion);
  t

let string_of_flags = P11_flags.(to_pretty_string Slot_info_domain)

let to_strings info =
  [
    "Slot Description", trim_and_quote info.slotDescription;
    "Manufacturer ID", trim_and_quote info.manufacturerID;
    "Flags", string_of_flags info.flags;
    "Firmware Version", P11_version.to_string info.firmwareVersion;
    "Hardware Version", P11_version.to_string info.hardwareVersion;
  ]

let to_string ?newlines ?indent info =
  Pkcs11_helpers.string_of_record ?newlines ?indent (to_strings info)

let to_strings info = Pkcs11_helpers.strings_of_record @@ to_strings info
