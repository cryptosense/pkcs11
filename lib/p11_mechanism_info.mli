type t =
  { ulMinKeySize : P11_ulong.t
  ; ulMaxKeySize : P11_ulong.t
  ; flags : P11_flags.t }
[@@deriving eq, ord, show, yojson]

val to_string : ?newlines:bool -> ?indent:string -> t -> string

val to_strings : t -> string list

val flags_to_string : P11_flags.t -> string

val flags_to_strings : P11_flags.t -> string list

(* flags possible to set for mechanism infos, aggregated *)
val allowed_flags : P11_flags.t
