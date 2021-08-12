type t = Unsigned.ULong.t [@@deriving ord]

let equal a b = compare a b = 0

let show = Unsigned.ULong.to_string

let pp fmt n = Format.pp_print_string fmt (show n)

let of_yojson = function
  | `String s -> Ok (Unsigned.ULong.of_string s)
  | _ -> Error "ulong_of_yojson: not a string"

let to_yojson ulong = `String (Unsigned.ULong.to_string ulong)

let to_string = Unsigned.ULong.to_string

let hash = Unsigned.ULong.to_int
