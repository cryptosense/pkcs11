open Ctypes

type _t

type t = _t structure

let ck_session_info : t typ = structure "CK_SESSION_INFO"

let ( -: ) ty label = Ctypes_helpers.smart_field ck_session_info label ty

let slotID = ulong -: "slotID"

let state = ulong -: "state"

let flags = Pkcs11_CK_FLAGS.typ -: "flags"

let ulDeviceError = ulong -: "ulDeviceError"

let () = seal ck_session_info

let view c =
  let open P11_session_info in
  { slotID = getf c slotID
  ; state = getf c state
  ; flags = getf c flags
  ; ulDeviceError = getf c ulDeviceError }

let make u =
  let open P11_session_info in
  let t = Ctypes.make ck_session_info in
  setf t slotID u.slotID;
  setf t state u.state;
  setf t flags u.flags;
  setf t ulDeviceError u.ulDeviceError;
  t
