type t =
  { label : string
  ; manufacturerID : string
  ; model : string
  ; serialNumber : string
  ; flags : P11_flags.t
  ; ulMaxSessionCount : P11_ulong.t
  ; ulSessionCount : P11_ulong.t
  ; ulMaxRwSessionCount : P11_ulong.t
  ; ulRwSessionCount : P11_ulong.t
  ; ulMaxPinLen : P11_ulong.t
  ; ulMinPinLen : P11_ulong.t
  ; ulTotalPublicMemory : P11_ulong.t
  ; ulFreePublicMemory : P11_ulong.t
  ; ulTotalPrivateMemory : P11_ulong.t
  ; ulFreePrivateMemory : P11_ulong.t
  ; hardwareVersion : P11_version.t
  ; firmwareVersion : P11_version.t
  ; utcTime : string }
[@@deriving eq, ord, show, yojson]

val ul_to_string : Unsigned.ULong.t -> string
(** Return correct string value if the unsigned long has a special value e.g.
    [CK_UNAVAILABLE_INFORMATION]. *)

val to_string : ?newlines:bool -> ?indent:string -> t -> string

val to_strings : t -> string list

val flags_to_string : P11_flags.t -> string
