open Ctypes
open Ctypes_helpers

type t =
  { length : ulong ptr
  ; mutable content : Pkcs11_CK_BYTE.t ptr }

let get_length t =
  assert (not (is_null t.length));
  !@(t.length)

let get_content t = t.content

let get_length_addr (t : t) : P11_ulong.t ptr = t.length

let string_from_ptr ~length x =
  string_from_ptr ~length (from_voidp char (to_voidp x))

let string_of_raw data len =
  let length = Unsigned.ULong.to_int len in
  let s = string_from_ptr ~length data in
  s

let to_string (t : t) : string = string_of_raw (get_content t) (get_length t)

let of_string (s : string) : t =
  let len = String.length s in
  let content = allocate_n char ~count:len in
  String.iteri (fun i c -> content +@ i <-@ c) s;
  {length = allocate ulong (Unsigned.ULong.of_int len); content}

let create () : t =
  { length = allocate ulong (Unsigned.ULong.of_int 0)
  ; content = from_voidp Pkcs11_CK_BYTE.typ null }

let allocate (t : t) : unit =
  let n = get_length t |> Unsigned.ULong.to_int in
  t.content <- allocate_n Pkcs11_CK_BYTE.typ ~count:n
