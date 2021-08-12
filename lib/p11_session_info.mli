type t =
  { slotID : P11_ulong.t
  ; state : P11_ulong.t
  ; flags : P11_flags.t
  ; ulDeviceError : P11_ulong.t }
[@@deriving eq, ord, show, yojson]

val to_string : ?newlines:bool -> ?indent:string -> t -> string

val to_strings : t -> string list
