type t =
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
  | CKO_CS_UNKNOWN of P11_ulong.t
[@@deriving eq, ord, show]

let to_string = function
  | CKO_DATA -> "CKO_DATA"
  | CKO_CERTIFICATE -> "CKO_CERTIFICATE"
  | CKO_PUBLIC_KEY -> "CKO_PUBLIC_KEY"
  | CKO_PRIVATE_KEY -> "CKO_PRIVATE_KEY"
  | CKO_SECRET_KEY -> "CKO_SECRET_KEY"
  | CKO_HW_FEATURE -> "CKO_HW_FEATURE"
  | CKO_DOMAIN_PARAMETERS -> "CKO_DOMAIN_PARAMETERS"
  | CKO_MECHANISM -> "CKO_MECHANISM"
  | CKO_OTP_KEY -> "CKO_OTP_KEY"
  | CKO_VENDOR_DEFINED -> "CKO_VENDOR_DEFINED"
  | CKO_CS_UNKNOWN x -> Unsigned.ULong.to_string x

let of_string = function
  | "CKO_DATA" -> CKO_DATA
  | "CKO_CERTIFICATE" -> CKO_CERTIFICATE
  | "CKO_PUBLIC_KEY" -> CKO_PUBLIC_KEY
  | "CKO_PRIVATE_KEY" -> CKO_PRIVATE_KEY
  | "CKO_SECRET_KEY" -> CKO_SECRET_KEY
  | "CKO_HW_FEATURE" -> CKO_HW_FEATURE
  | "CKO_DOMAIN_PARAMETERS" -> CKO_DOMAIN_PARAMETERS
  | "CKO_MECHANISM" -> CKO_MECHANISM
  | "CKO_OTP_KEY" -> CKO_OTP_KEY
  | "CKO_VENDOR_DEFINED" -> CKO_VENDOR_DEFINED
  | x -> (
    try CKO_CS_UNKNOWN (Unsigned.ULong.of_string x) with
    | Sys.Break as e -> raise e
    | _ ->
      invalid_arg ("Pkcs11_CK_OBJECT_CLASS.of_string" ^ ": cannot find " ^ x))

let to_yojson object_class = `String (to_string object_class)

let of_yojson = P11_helpers.of_json_string ~typename:"object class" of_string
