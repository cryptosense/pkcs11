type t =
  { slotID : Pkcs11_CK_ULONG.t
  ; state : Pkcs11_CK_ULONG.t
  ; flags : P11_flags.t
  ; ulDeviceError : Pkcs11_CK_ULONG.t;
  }
[@@deriving yojson]

val to_string : ?newlines: bool -> ?indent: string -> t -> string

val to_strings : t -> string list
