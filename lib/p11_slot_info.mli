type t =
  { slotDescription : string
  ; manufacturerID : string
  ; flags : P11_flags.t
  ; hardwareVersion : P11_version.t
  ; firmwareVersion : P11_version.t }
[@@deriving eq, ord, show, yojson]

val to_string : ?newlines:bool -> ?indent:string -> t -> string

val to_strings : t -> string list

val flags_to_string : P11_flags.t -> string
