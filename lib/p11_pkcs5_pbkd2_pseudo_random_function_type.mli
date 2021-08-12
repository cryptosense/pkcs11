type t = CKP_PKCS5_PBKD2_HMAC_SHA1 [@@deriving eq, ord, show, yojson]

val to_string : t -> string

val of_string : string -> t
