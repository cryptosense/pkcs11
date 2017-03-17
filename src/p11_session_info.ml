type t = Pkcs11.CK_SESSION_INFO.u =
  {
    slotID : Pkcs11_CK_ULONG.t;
    state : Pkcs11_CK_ULONG.t;
    flags : P11_flags.t;
    ulDeviceError : Pkcs11_CK_ULONG.t;
  }
  [@@deriving of_yojson]

let to_string = Pkcs11.CK_SESSION_INFO.to_string
let to_strings = Pkcs11.CK_SESSION_INFO.to_strings

let to_yojson info =
  `Assoc [
    "slotID", `String (info.slotID |> Unsigned.ULong.to_string );
    "state", `String (info.state |> Unsigned.ULong.to_string);
    "flags",
    P11_flags.to_json ~pretty: Pkcs11.CK_SESSION_INFO.string_of_flags info.flags;
    "ulDeviceError", `String (info.ulDeviceError |> Unsigned.ULong.to_string);
  ]
