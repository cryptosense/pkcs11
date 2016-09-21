open Ctypes
open Ctypes_helpers

type _t

type t = _t Ctypes.structure

let t : t typ = structure "data"
let (-:) ty label = Ctypes_helpers.smart_field t label ty
let length = ulong -: "length"
let content = ptr Pkcs11_CK_BYTE.typ -: "content"
let () = seal t


(* accessors *)
let get_length (t:t) : Pkcs11_CK_ULONG.t =
  getf t length

let get_content (t:t) : Pkcs11_CK_BYTE.t ptr =
  getf t content

let get_length_addr (t:t) : Pkcs11_CK_ULONG.t ptr =
  t @. length

let string_from_ptr ~length x =
  string_from_ptr ~length (from_voidp char (to_voidp x))

let string_of_raw data len =
  let length = Unsigned.ULong.to_int len in
  let s = string_from_ptr ~length data in
  s

let to_string (t:t) : string =
  string_of_raw (get_content t) (get_length t)

let of_string (s:string) : t =
  let t = make t in
  make_string s t length content;
  t

let create () : t =
  let t = make t in
  setf t length (Unsigned.ULong.zero);
  setf t content (from_voidp Pkcs11_CK_BYTE.typ null);
  t

let allocate (t:t) : unit =
  let n = get_length t |> Unsigned.ULong.to_int in
  let data = allocate_n Pkcs11_CK_BYTE.typ ~count:n in
  setf t content data;
  ()
