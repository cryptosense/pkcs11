type t =
  { bits: P11_ulong.t
  ; block: string
  }
[@@deriving eq,make,ord,show,yojson]

let bits x = x.bits
let block x = x.block
