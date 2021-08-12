type t =
  { saltSource : P11_pkcs5_pbkdf2_salt_source_type.t
  ; saltSourceData : string option
  ; iterations : int
  ; prf : P11_pkcs5_pbkd2_pseudo_random_function_type.t
  ; prfData : string option
  ; password : string }
[@@deriving eq, ord, show, yojson]
