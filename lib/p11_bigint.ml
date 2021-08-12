type t = Z.t

let string_reverse s =
  let n = String.length s in
  String.init n (fun i -> s.[n - 1 - i])

let string_count_trailing c s =
  let rec go acc i =
    if i >= 0 && s.[i] = c then
      go (acc + 1) (i - 1)
    else
      acc
  in
  let n = String.length s in
  go 0 (n - 1)

let string_remove_trailing c s =
  let n = String.length s in
  let k = string_count_trailing c s in
  Str.first_chars s (n - k)

(*
    PKCS#11 expects numbers to be encoded in big endian.
    Also, Zarith adds trailing zeroes in Z.to_bits.
 *)
let encode z = string_reverse @@ string_remove_trailing '\x00' @@ Z.to_bits z

let decode s = Z.of_bits @@ string_reverse s

let to_int = Z.to_int

let of_int = Z.of_int

let to_yojson z = P11_hex_data.to_yojson @@ encode z

let of_yojson j =
  let open Ppx_deriving_yojson_runtime in
  P11_hex_data.of_yojson j >|= decode

let equal = Z.equal

let compare = Z.compare

let to_string = Z.to_string

let zero = Z.zero

let of_z z = z

let to_z z = z

let show = to_string

let pp fmt x = Format.fprintf fmt "%s" (show x)
