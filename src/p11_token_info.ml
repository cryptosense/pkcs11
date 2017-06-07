type t =
  { label : string
  ; manufacturerID : string
  ; model : string
  ; serialNumber : string
  ; flags : P11_flags.t
  ; ulMaxSessionCount : P11_ulong.t
  ; ulSessionCount : P11_ulong.t
  ; ulMaxRwSessionCount : P11_ulong.t
  ; ulRwSessionCount : P11_ulong.t
  ; ulMaxPinLen : P11_ulong.t
  ; ulMinPinLen : P11_ulong.t
  ; ulTotalPublicMemory : P11_ulong.t
  ; ulFreePublicMemory : P11_ulong.t
  ; ulTotalPrivateMemory : P11_ulong.t
  ; ulFreePrivateMemory : P11_ulong.t
  ; hardwareVersion : P11_version.t
  ; firmwareVersion : P11_version.t
  ; utcTime : string
  }
[@@deriving of_yojson]

let flags_to_string = P11_flags.(to_pretty_string Token_info_domain)

let ul_to_string t =
  P11_ulong.(
    if is_effectively_infinite t then
      "CK_EFFECTIVELY_INFINITE"
    else if is_unavailable_information t then
      "CK_UNAVAILABLE_INFORMATION"
    else
      Unsigned.ULong.to_string t
  )

let to_strings info =
  let open Ctypes_helpers in
  [
    "Label", trim_and_quote info.label;
    "Manufacturer ID", trim_and_quote info.manufacturerID;
    "Model", trim_and_quote info.model;
    "Serial Number", trim_and_quote info.serialNumber;
    "Flags", flags_to_string info.flags;
    "Maximum Session Count", ul_to_string info.ulMaxSessionCount;
    "Session count", ul_to_string info.ulSessionCount;
    "Maximum Read-Write Session Count", ul_to_string info.ulMaxRwSessionCount;
    "Read-Write Session Count", ul_to_string info.ulRwSessionCount;
    "Maximum PIN Length", Unsigned.ULong.to_string info.ulMaxPinLen;
    "Minimim PIN Length", Unsigned.ULong.to_string info.ulMinPinLen;
    "Total Public Memory", ul_to_string info.ulTotalPublicMemory;
    "Free Public Memory", ul_to_string info.ulFreePublicMemory;
    "Total Private Memory", ul_to_string info.ulTotalPrivateMemory;
    "Free Private Memory", ul_to_string info.ulFreePrivateMemory;
    "Hardware Version", (P11_version.to_string info.hardwareVersion);
    "Firmware Version", (P11_version.to_string info.firmwareVersion);
    "UTC Time", trim_and_quote info.utcTime;
  ]

let to_string ?newlines ?indent info =
  Pkcs11_helpers.string_of_record ?newlines ?indent (to_strings info)

let to_strings info = Pkcs11_helpers.strings_of_record @@ to_strings info

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
