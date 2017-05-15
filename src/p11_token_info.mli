type t = Pkcs11.CK_TOKEN_INFO.u =
  {
    label : string;
    manufacturerID : string;
    model : string;
    serialNumber : string;
    flags : P11_flags.t;
    ulMaxSessionCount : Unsigned.ULong.t;
    ulSessionCount : Unsigned.ULong.t;
    ulMaxRwSessionCount : Unsigned.ULong.t;
    ulRwSessionCount : Unsigned.ULong.t;
    ulMaxPinLen : Unsigned.ULong.t;
    ulMinPinLen : Unsigned.ULong.t;
    ulTotalPublicMemory : Unsigned.ULong.t;
    ulFreePublicMemory : Unsigned.ULong.t;
    ulTotalPrivateMemory : Unsigned.ULong.t;
    ulFreePrivateMemory : Unsigned.ULong.t;
    hardwareVersion : P11_version.t;
    firmwareVersion : P11_version.t;
    utcTime : string;
  }
[@@deriving yojson]
val ul_to_string : Unsigned.ULong.t -> string
val to_string : ?newlines: bool -> ?indent: string -> t -> string
val to_strings : t -> string list
val flags_to_string : P11_flags.t -> string
