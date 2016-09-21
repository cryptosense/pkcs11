open Ctypes
open Pkcs11_helpers

type _t
type t = _t structure

let ck_session_info : t typ = structure "CK_SESSION_INFO"
let (-:) ty label = Ctypes_helpers.smart_field ck_session_info label ty

let slotID        = ulong    -: "slotID"
let state         = ulong    -: "state"
let flags         = Pkcs11_CK_FLAGS.t -: "flags"
let ulDeviceError = ulong    -: "ulDeviceError"
let () = seal ck_session_info

type u =
  {
    slotID: Unsigned.ULong.t;
    state: Unsigned.ULong.t;
    flags: Pkcs11_CK_FLAGS.t;
    ulDeviceError: Unsigned.ULong.t;
  }


let view (c: t) : u =
  {
    slotID = getf c slotID;

    state = getf c state;

    flags = getf c flags;

    ulDeviceError = getf c ulDeviceError;
  }

let make (u : u) : t =
  let t = Ctypes.make ck_session_info in
  setf t slotID u.slotID;
  setf t state  u.state;
  setf t flags u.flags;
  setf t ulDeviceError u.ulDeviceError;
  t

let string_of_flags = Pkcs11_CK_FLAGS.(to_pretty_string Session_info_domain)

let to_strings info =
  [
    "Slot ID", Unsigned.ULong.to_string info.slotID;
    "State", Unsigned.ULong.to_string info.state;
    "Flags", string_of_flags info.flags;
    "Device Error", Unsigned.ULong.to_string info.ulDeviceError;
  ]

let to_string ?newlines ?indent info =
  string_of_record ?newlines ?indent (to_strings info)

let to_strings info = strings_of_record @@ to_strings info
