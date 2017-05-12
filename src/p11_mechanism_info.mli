type t =
  { ulMinKeySize : Pkcs11_CK_ULONG.t
  ; ulMaxKeySize : Pkcs11_CK_ULONG.t
  ; flags : P11_flags.t
  }
[@@deriving yojson]

val to_string : ?newlines: bool -> ?indent: string -> t -> string

val to_strings :  t -> string list

val flags_to_string : P11_flags.t -> string

val flags_to_strings : P11_flags.t -> string list

(* flags possible to set for mechanism infos, aggregated *)
val allowed_flags : P11_flags.t
