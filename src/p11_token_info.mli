type t =
  { label : string
  ; manufacturerID : string
  ; model : string
  ; serialNumber : string
  ; flags : P11_flags.t
  ; ulMaxSessionCount : Pkcs11_CK_ULONG.t
  ; ulSessionCount : Pkcs11_CK_ULONG.t
  ; ulMaxRwSessionCount : Pkcs11_CK_ULONG.t
  ; ulRwSessionCount : Pkcs11_CK_ULONG.t
  ; ulMaxPinLen : Pkcs11_CK_ULONG.t
  ; ulMinPinLen : Pkcs11_CK_ULONG.t
  ; ulTotalPublicMemory : Pkcs11_CK_ULONG.t
  ; ulFreePublicMemory : Pkcs11_CK_ULONG.t
  ; ulTotalPrivateMemory : Pkcs11_CK_ULONG.t
  ; ulFreePrivateMemory : Pkcs11_CK_ULONG.t
  ; hardwareVersion : P11_version.t
  ; firmwareVersion : P11_version.t
  ; utcTime : string
  }
[@@deriving yojson]

(** Return correct string value if the unsigned long has a special value e.g.
    [CK_UNAVAILABLE_INFORMATION]. *)
val ul_to_string : Unsigned.ULong.t -> string

val to_string : ?newlines: bool -> ?indent: string -> t -> string

val to_strings : t -> string list

val flags_to_string : P11_flags.t -> string
