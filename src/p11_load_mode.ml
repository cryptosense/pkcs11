type t =
  | Auto
  | Stubs
  | FFI
[@@deriving eq,ord,show,yojson]

let auto = Auto

let stubs = Stubs

let ffi = FFI
