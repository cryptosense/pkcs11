open Ctypes
open Ctypes_helpers

type _t

type t = _t structure

let t : t typ = structure "CK_KEY_DERIVATION_STRING_DATA"

let ( -: ) typ label = smart_field t label typ

let pData = Reachable_ptr.typ Pkcs11_CK_BYTE.typ -: "pData"

let ulLen = ulong -: "ulLen"

let () = seal t

type u = string

let make (u : u) : t =
  let t = make t in
  let data = ptr_from_string u in
  Reachable_ptr.setf t pData data;
  setf t ulLen (Unsigned.ULong.of_int @@ String.length u);
  t

let view (t : t) : u =
  string_from_ptr
    ~length:(getf t ulLen |> Unsigned.ULong.to_int)
    (Reachable_ptr.getf t pData)
