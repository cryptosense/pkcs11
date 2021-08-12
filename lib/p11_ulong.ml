type t = Unsigned.ULong.t [@@deriving ord]

let equal a b = compare a b = 0

let show = Unsigned.ULong.to_string

let pp fmt n = Format.pp_print_string fmt (show n)

let of_yojson = function
  | `String s -> Ok (Unsigned.ULong.of_string s)
  | _ -> Error "ulong_of_yojson: not a string"

let to_yojson ulong = `String (Unsigned.ULong.to_string ulong)

let _CK_UNAVAILABLE_INFORMATION = Unsigned.ULong.max_int

let _CK_EFFECTIVELY_INFINITE = Unsigned.ULong.zero

let is_unavailable_information t = compare t _CK_UNAVAILABLE_INFORMATION = 0

let is_effectively_infinite t = compare t _CK_EFFECTIVELY_INFINITE = 0
