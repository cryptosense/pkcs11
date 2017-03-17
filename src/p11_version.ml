type t = Pkcs11.CK_VERSION.u = { major : int; minor : int; }
[@@deriving eq,show,yojson]

let to_string = Pkcs11.CK_VERSION.to_string
