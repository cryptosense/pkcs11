open Ctypes

type _t

type t = _t structure

let ck_mechanism_info : t typ = structure "CK_MECHANISM_INFO"

let ( -: ) ty label = Ctypes_helpers.smart_field ck_mechanism_info label ty

let ulMinKeySize = ulong -: "ulMinKeySize"

let ulMaxKeySize = ulong -: "ulMaxKeySize"

let flags = Pkcs11_CK_FLAGS.typ -: "flags"

let () = seal ck_mechanism_info

let view c =
  let open P11_mechanism_info in
  { ulMinKeySize = getf c ulMinKeySize
  ; ulMaxKeySize = getf c ulMaxKeySize
  ; flags = getf c flags }

let make u =
  let open P11_mechanism_info in
  let t = Ctypes.make ck_mechanism_info in
  setf t ulMinKeySize u.ulMinKeySize;
  setf t ulMaxKeySize u.ulMaxKeySize;
  setf t flags u.flags;
  t
