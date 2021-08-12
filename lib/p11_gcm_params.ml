type t =
  { iv : P11_hex_data.t
  ; aad : P11_hex_data.t
  ; tag_bits : P11_ulong.t }
[@@deriving eq, ord, make, show, yojson]

let iv x = x.iv

let aad x = x.aad

let tag_bits x = x.tag_bits
