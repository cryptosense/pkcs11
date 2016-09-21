type t = Pkcs11_CK_ULONG.t

type u =
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

  | CKO_CS_UNKNOWN of Unsigned.ULong.t
  (** This is a catch-all case that makes it possible to deal with
      vendor-specific/non-standard CKO. *)

val _CKO_DATA : t
val _CKO_CERTIFICATE : t
val _CKO_PUBLIC_KEY : t
val _CKO_PRIVATE_KEY : t
val _CKO_SECRET_KEY : t
val _CKO_HW_FEATURE : t
val _CKO_DOMAIN_PARAMETERS : t
val _CKO_MECHANISM : t
val _CKO_OTP_KEY : t
val _CKO_VENDOR_DEFINED : t

include P11_sigs.PKCS with type t := t and type u := u

val typ : t Ctypes.typ
