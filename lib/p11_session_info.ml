let string_of_flags = P11_flags.(to_pretty_string Session_info_domain)

let session_info_flags_to_yojson flags =
  P11_flags.to_json ~pretty:string_of_flags flags

type session_info_flags = P11_flags.t [@@deriving eq, ord, show, of_yojson]

type t =
  { slotID : P11_ulong.t
  ; state : P11_ulong.t
  ; flags : session_info_flags
  ; ulDeviceError : P11_ulong.t }
[@@deriving eq, ord, show, yojson]

let to_strings info =
  [ ("Slot ID", Unsigned.ULong.to_string info.slotID)
  ; ("State", Unsigned.ULong.to_string info.state)
  ; ("Flags", string_of_flags info.flags)
  ; ("Device Error", Unsigned.ULong.to_string info.ulDeviceError) ]

let to_string ?newlines ?indent info =
  P11_helpers.string_of_record ?newlines ?indent (to_strings info)

let to_strings info = P11_helpers.strings_of_record @@ to_strings info
