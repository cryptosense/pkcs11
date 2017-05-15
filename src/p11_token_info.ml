type t = Pkcs11.CK_TOKEN_INFO.u =
  {
    label : string;
    manufacturerID : string;
    model : string;
    serialNumber : string;
    flags : P11_flags.t;
    ulMaxSessionCount : Pkcs11_CK_ULONG.t;
    ulSessionCount : Pkcs11_CK_ULONG.t;
    ulMaxRwSessionCount : Pkcs11_CK_ULONG.t;
    ulRwSessionCount : Pkcs11_CK_ULONG.t;
    ulMaxPinLen : Pkcs11_CK_ULONG.t;
    ulMinPinLen : Pkcs11_CK_ULONG.t;
    ulTotalPublicMemory : Pkcs11_CK_ULONG.t;
    ulFreePublicMemory : Pkcs11_CK_ULONG.t;
    ulTotalPrivateMemory : Pkcs11_CK_ULONG.t;
    ulFreePrivateMemory : Pkcs11_CK_ULONG.t;
    hardwareVersion : P11_version.t;
    firmwareVersion : P11_version.t;
    utcTime : string;
  }
  [@@deriving of_yojson]

let ul_to_string = Pkcs11.CK_TOKEN_INFO.ul_to_string
let to_string = Pkcs11.CK_TOKEN_INFO.to_string
let to_strings = Pkcs11.CK_TOKEN_INFO.to_strings
let flags_to_string = Pkcs11.CK_TOKEN_INFO.string_of_flags

let to_yojson info =
  let ulong x = `String (Unsigned.ULong.to_string x) in
  `Assoc [
    "label", `String info.label;
    "manufacturerID", `String info.manufacturerID;
    "model", `String info.model;
    "serialNumber", `String info.serialNumber;
    "flags",
    P11_flags.to_json ~pretty:flags_to_string info.flags;
    "ulMaxSessionCount", ulong info.ulMaxSessionCount;
    "ulSessionCount", ulong info.ulSessionCount;
    "ulMaxRwSessionCount", ulong info.ulMaxRwSessionCount;
    "ulRwSessionCount", ulong info.ulRwSessionCount;
    "ulMaxPinLen", ulong info.ulMaxPinLen;
    "ulMinPinLen", ulong info.ulMinPinLen;
    "ulTotalPublicMemory", ulong info.ulTotalPublicMemory;
    "ulFreePublicMemory", ulong info.ulFreePublicMemory;
    "ulTotalPrivateMemory", ulong info.ulTotalPrivateMemory;
    "ulFreePrivateMemory", ulong info.ulFreePrivateMemory;
    "hardwareVersion", P11_version.to_yojson info.hardwareVersion;
    "firmwareVersion", P11_version.to_yojson info.firmwareVersion;
    "utcTime", `String info.utcTime;
  ]
