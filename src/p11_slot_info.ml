type t = Pkcs11.CK_SLOT_INFO.u =
  {
    slotDescription : string;
    manufacturerID : string;
    flags : P11_flags.t;
    hardwareVersion : P11_version.t;
    firmwareVersion : P11_version.t;
  }
  [@@deriving of_yojson]

let to_string = Pkcs11.CK_SLOT_INFO.to_string
let to_strings = Pkcs11.CK_SLOT_INFO.to_strings
let flags_to_string = Pkcs11.CK_SLOT_INFO.string_of_flags

let to_yojson info =
  `Assoc [
    "slotDescription", `String info.slotDescription;
    "manufacturerID", `String info.manufacturerID;
    "flags",
    P11_flags.to_json ~pretty:flags_to_string info.flags;
    "hardwareVersion", P11_version.to_yojson info.hardwareVersion;
    "firmwareVersion", P11_version.to_yojson info.firmwareVersion;
  ]
