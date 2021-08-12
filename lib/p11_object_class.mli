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
  | CKO_CS_UNKNOWN of Unsigned.ULong.t
[@@deriving eq, ord, show, yojson]

val of_string : string -> t

val to_string : t -> string
