type t = Pkcs11.CK_VERSION.u =
  { major : int; minor : int; }
[@@deriving eq,show,yojson]
val to_string : t -> string
