type t =
  { slotID : Pkcs11_CK_ULONG.t
  ; state : Pkcs11_CK_ULONG.t
  ; flags : P11_flags.t
  ; ulDeviceError : Pkcs11_CK_ULONG.t;
  }
[@@deriving of_yojson]

let string_of_flags = P11_flags.(to_pretty_string Session_info_domain)

let to_strings info =
  [
    "Slot ID", Unsigned.ULong.to_string info.slotID;
    "State", Unsigned.ULong.to_string info.state;
    "Flags", string_of_flags info.flags;
    "Device Error", Unsigned.ULong.to_string info.ulDeviceError;
  ]

let to_string ?newlines ?indent info =
  Pkcs11_helpers.string_of_record ?newlines ?indent (to_strings info)

let to_strings info = Pkcs11_helpers.strings_of_record @@ to_strings info

let to_yojson info =
  `Assoc
    [ "slotID", `String (info.slotID |> Unsigned.ULong.to_string )
    ; "state", `String (info.state |> Unsigned.ULong.to_string)
    ; "flags", P11_flags.to_json ~pretty: string_of_flags info.flags
    ; "ulDeviceError", `String (info.ulDeviceError |> Unsigned.ULong.to_string)
    ]
