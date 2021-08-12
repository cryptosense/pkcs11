type t = string [@@deriving eq, ord, show]

let normalize s =
  if s = "" then
    ""
  else
    (* Remove leading zeros. *)
    let len = String.length s in
    let rec first_non_zero i =
      if i >= len then
        (* Keep at least one 0. *)
        len - 1
      else if s.[i] = '\000' then
        first_non_zero (i + 1)
      else
        i
    in
    let first_non_zero = first_non_zero 0 in
    String.sub s first_non_zero (len - first_non_zero)

let to_yojson data =
  let (`Hex h) = Hex.of_string data in
  `String ("0x" ^ h)

exception Invalid_hex

let of_yojson =
  let err msg = Error ("P11_hex_data: " ^ msg) in
  function
  | `String s when String.length s < 2 ->
    err "string does not start with \"0x\""
  | `String s when s.[0] = '0' && s.[1] = 'x' -> (
    let data = Str.string_after s 2 in
    try
      String.iter
        (function
          | '0' .. '9'
          | 'a' .. 'f'
          | 'A' .. 'F' ->
            ()
          | _ -> raise Invalid_hex)
        data;
      Ok (Hex.to_string @@ `Hex data)
    with
    | Invalid_hex
    | Invalid_argument _ ->
      err "not valid hex-encoded data")
  | `String _ -> err "string does not start with \"0x\""
  | _ -> err "not a string"
