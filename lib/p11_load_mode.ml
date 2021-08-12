type t =
  | Auto
  | FFI
[@@deriving eq, ord, show, yojson]

let auto = Auto

let ffi = FFI
