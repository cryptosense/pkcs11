type t =
  { ulMinKeySize : P11_ulong.t
  ; ulMaxKeySize : P11_ulong.t
  ; flags : P11_flags.t }
[@@deriving eq, ord, show, of_yojson]

let allowed_flags =
  let flags = P11_flags.(flags_of_domain Mechanism_info_domain) in
  let flags = List.map fst flags in
  List.fold_left P11_flags.logical_or P11_flags.empty flags

let flags_to_string = P11_flags.(to_pretty_string Mechanism_info_domain)

let flags_to_strings = P11_flags.(to_pretty_strings Mechanism_info_domain)

let to_strings info =
  [ ("Minimum Key Size", Unsigned.ULong.to_string info.ulMinKeySize)
  ; ("Maximum Key Size", Unsigned.ULong.to_string info.ulMaxKeySize)
  ; ("Flags", flags_to_string info.flags) ]

let to_string ?newlines ?indent info =
  P11_helpers.string_of_record ?newlines ?indent (to_strings info)

let to_strings info = to_strings info |> P11_helpers.strings_of_record

let to_yojson info =
  `Assoc
    [ ("ulMinKeySize", `String (info.ulMinKeySize |> Unsigned.ULong.to_string))
    ; ("ulMaxKeySize", `String (info.ulMaxKeySize |> Unsigned.ULong.to_string))
    ; ("flags", P11_flags.to_json ~pretty:flags_to_string info.flags) ]
