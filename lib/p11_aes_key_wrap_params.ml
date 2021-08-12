type t = P11_hex_data.t option [@@deriving eq, ord, show, yojson]

let default = None

let explicit iv = Some iv

let explicit_iv x = x
