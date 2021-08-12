let flags_to_string = P11_flags.(to_pretty_string Slot_info_domain)

type slot_info_flags = P11_flags.t [@@deriving eq, ord, show, of_yojson]

let slot_info_flags_to_yojson flags =
  P11_flags.to_json ~pretty:flags_to_string flags

type t =
  { slotDescription : string
  ; manufacturerID : string
  ; flags : slot_info_flags
  ; hardwareVersion : P11_version.t
  ; firmwareVersion : P11_version.t }
[@@deriving eq, ord, show, yojson]

let to_strings info =
  [ ("Slot Description", P11_helpers.trim_and_quote info.slotDescription)
  ; ("Manufacturer ID", P11_helpers.trim_and_quote info.manufacturerID)
  ; ("Flags", flags_to_string info.flags)
  ; ("Firmware Version", P11_version.to_string info.firmwareVersion)
  ; ("Hardware Version", P11_version.to_string info.hardwareVersion) ]

let to_string ?newlines ?indent info =
  P11_helpers.string_of_record ?newlines ?indent (to_strings info)

let to_strings info = P11_helpers.strings_of_record @@ to_strings info
