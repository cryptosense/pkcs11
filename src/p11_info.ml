type t =
  { cryptokiVersion : P11_version.t
  ; manufacturerID : string
  ; flags : P11_flags.t
  ; libraryDescription : string
  ; libraryVersion : P11_version.t
  }
[@@deriving eq,show,of_yojson]

let flags_to_string = P11_flags.(to_pretty_string Info_domain)

let to_strings info =
  [
    "Version", P11_version.to_string info.cryptokiVersion;
    "Manufacturer ID", Ctypes_helpers.trim_and_quote info.manufacturerID;
    "Flags", flags_to_string info.flags;
    "Library Description", Ctypes_helpers.trim_and_quote info.libraryDescription;
    "Library Version", P11_version.to_string info.libraryVersion;
  ]

let to_string ?newlines ?indent info =
  P11_helpers.string_of_record ?newlines ?indent (to_strings info)

let to_strings info = to_strings info |> P11_helpers.strings_of_record

let to_yojson info =
  `Assoc [
    "cryptokiVersion", P11_version.to_yojson info.cryptokiVersion;
    "manufacturerID", `String info.manufacturerID;
    "flags", P11_flags.to_json ~pretty:flags_to_string info.flags;
    "libraryDescription", `String info.libraryDescription;
    "libraryVersion", P11_version.to_yojson info.libraryVersion;
  ]
