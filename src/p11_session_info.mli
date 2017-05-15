type t = Pkcs11.CK_SESSION_INFO.u =
  {
    slotID : Unsigned.ULong.t;
    state : Unsigned.ULong.t;
    flags : P11_flags.t;
    ulDeviceError : Unsigned.ULong.t;
  }
[@@deriving yojson]
val to_string : ?newlines: bool -> ?indent: string -> t -> string
val to_strings : t -> string list
