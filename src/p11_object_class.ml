type t = Pkcs11.CK_OBJECT_CLASS.u =
  | CKO_DATA
  | CKO_CERTIFICATE
  | CKO_PUBLIC_KEY
  | CKO_PRIVATE_KEY
  | CKO_SECRET_KEY
  | CKO_HW_FEATURE
  | CKO_DOMAIN_PARAMETERS
  | CKO_MECHANISM
  | CKO_OTP_KEY
  | CKO_VENDOR_DEFINED
  (* This is a catch-all case that makes it possible to deal with
     vendor-specific/non-standard CKO. *)
  | CKO_CS_UNKNOWN of Pkcs11.CK_ULONG.t
[@@deriving show]

let equal = (Pervasives.(=): t -> t -> bool)
let compare = (Pervasives.compare: t -> t -> int)

let to_string = Pkcs11.CK_OBJECT_CLASS.to_string
let of_string = Pkcs11.CK_OBJECT_CLASS.of_string

let to_yojson object_class =
  `String (to_string object_class)

let of_yojson = Ctypes_helpers.of_json_string ~typename:"object class" of_string
