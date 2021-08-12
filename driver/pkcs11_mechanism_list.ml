open Ctypes

type _t

type t =
  { length : P11_ulong.t ptr
  ; mutable content : Pkcs11_CK_MECHANISM_TYPE.t ptr }

type u = P11_mechanism_type.t list

let get_length (t : t) : P11_ulong.t = !@(t.length)

let get_content (t : t) : Pkcs11_CK_MECHANISM_TYPE.t ptr = t.content

let get_length_addr (t : t) : P11_ulong.t ptr = t.length

let create () : t =
  { length = Ctypes.allocate ulong Unsigned.ULong.zero
  ; content = from_voidp Pkcs11_CK_MECHANISM_TYPE.typ null }

let allocate (t : t) : unit =
  let n = get_length t |> Unsigned.ULong.to_int in
  let data = allocate_n Pkcs11_CK_MECHANISM_TYPE.typ ~count:n in
  t.content <- data;
  ()

let of_raw content length = {length; content}

let view (t : t) : u =
  let length = get_length t |> Unsigned.ULong.to_int in
  let array = CArray.from_ptr (get_content t) length in
  List.map Pkcs11_CK_MECHANISM_TYPE.view @@ CArray.to_list array

let make (u : u) : t =
  let array =
    u
    |> List.map Pkcs11_CK_MECHANISM_TYPE.make
    |> CArray.of_list Pkcs11_CK_MECHANISM_TYPE.typ
  in
  { length = Ctypes.allocate ulong (Unsigned.ULong.of_int (List.length u))
  ; content = CArray.start array }
