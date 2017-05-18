type t =
  { slotDescription : string
  ; manufacturerID : string
  ; flags : P11_flags.t
  ; hardwareVersion : P11_version.t
  ; firmwareVersion : P11_version.t
  }
[@@deriving of_yojson]

let flags_to_string = P11_flags.(to_pretty_string Slot_info_domain)

let to_strings info =
  let open Ctypes_helpers in
  [ "Slot Description", trim_and_quote info.slotDescription
  ; "Manufacturer ID", trim_and_quote info.manufacturerID
  ; "Flags", flags_to_string info.flags
  ; "Firmware Version", P11_version.to_string info.firmwareVersion
  ; "Hardware Version", P11_version.to_string info.hardwareVersion
  ]

let to_string ?newlines ?indent info =
  Pkcs11_helpers.string_of_record ?newlines ?indent (to_strings info)

let to_strings info = Pkcs11_helpers.strings_of_record @@ to_strings info

let to_yojson info =
  `Assoc
    [ "slotDescription", `String info.slotDescription
    ; "manufacturerID", `String info.manufacturerID
    ; "flags", P11_flags.to_json ~pretty:flags_to_string info.flags
    ; "hardwareVersion", P11_version.to_yojson info.hardwareVersion
    ; "firmwareVersion", P11_version.to_yojson info.firmwareVersion
    ]
