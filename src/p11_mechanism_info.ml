type t = Pkcs11.CK_MECHANISM_INFO.u =
  {
    ulMinKeySize : Pkcs11_CK_ULONG.t;
    ulMaxKeySize : Pkcs11_CK_ULONG.t;
    flags : P11_flags.t;
  }
  [@@deriving of_yojson]

let to_string = Pkcs11.CK_MECHANISM_INFO.to_string
let to_strings = Pkcs11.CK_MECHANISM_INFO.to_strings
let flags_to_string = Pkcs11.CK_MECHANISM_INFO.string_of_flags
let flags_to_strings = Pkcs11.CK_MECHANISM_INFO.strings_of_flags
let allowed_flags = Pkcs11.CK_MECHANISM_INFO.allowed_flags

let to_yojson info =
  `Assoc [
    "ulMinKeySize", `String (info.ulMinKeySize |> Unsigned.ULong.to_string );
    "ulMaxKeySize", `String (info.ulMaxKeySize |> Unsigned.ULong.to_string );
    "flags",
    P11_flags.to_json ~pretty:flags_to_string info.flags;
  ]
