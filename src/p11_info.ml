type t = Pkcs11.CK_INFO.u =
  {
    cryptokiVersion : P11_version.t;
    manufacturerID : string;
    flags : P11_flags.t;
    libraryDescription : string;
    libraryVersion : P11_version.t;
  }
  [@@deriving eq,show,of_yojson]

let to_string = Pkcs11.CK_INFO.to_string
let to_strings = Pkcs11.CK_INFO.to_strings
let flags_to_string = Pkcs11.CK_INFO.string_of_flags

let to_yojson info =
  `Assoc [
    "cryptokiVersion", P11_version.to_yojson info.cryptokiVersion;
    "manufacturerID", `String info.manufacturerID;
    "flags", P11_flags.to_json ~pretty:flags_to_string info.flags;
    "libraryDescription", `String info.libraryDescription;
    "libraryVersion", P11_version.to_yojson info.libraryVersion;
  ]
