type t =
  { bits : P11_ulong.t
  ; block : P11_hex_data.t }
[@@deriving eq, make, ord, show, yojson]

let bits x = x.bits

let block x = x.block
