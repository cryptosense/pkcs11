(** Key types ([CK_KEY_TYPE]) *)

type t = Pkcs11_CK_ULONG.t

type u =
  | CKK_RSA
  | CKK_DSA
  | CKK_DH
  | CKK_EC
  | CKK_X9_42_DH
  | CKK_KEA
  | CKK_GENERIC_SECRET
  | CKK_RC2
  | CKK_RC4
  | CKK_DES
  | CKK_DES2
  | CKK_DES3
  | CKK_CAST
  | CKK_CAST3
  | CKK_CAST128
  | CKK_RC5
  | CKK_IDEA
  | CKK_SKIPJACK
  | CKK_BATON
  | CKK_JUNIPER
  | CKK_CDMF
  | CKK_AES
  | CKK_BLOWFISH
  | CKK_TWOFISH
  | CKK_SECURID
  | CKK_HOTP
  | CKK_ACTI
  | CKK_CAMELLIA
  | CKK_ARIA
  | CKK_VENDOR_DEFINED

  (* This is a catch-all case that makes it possible to deal with
     vendor-specific/non-standard CKK. *)
  | CKK_CS_UNKNOWN of Unsigned.ULong.t

val _CKK_RSA : t
val _CKK_DSA : t
val _CKK_DH : t
val _CKK_EC : t
val _CKK_X9_42_DH : t
val _CKK_KEA : t
val _CKK_GENERIC_SECRET : t
val _CKK_RC2 : t
val _CKK_RC4 : t
val _CKK_DES : t
val _CKK_DES2 : t
val _CKK_DES3 : t
val _CKK_CAST : t
val _CKK_CAST3 : t
val _CKK_CAST128 : t
val _CKK_RC5 : t
val _CKK_IDEA : t
val _CKK_SKIPJACK : t
val _CKK_BATON : t
val _CKK_JUNIPER : t
val _CKK_CDMF : t
val _CKK_AES : t
val _CKK_BLOWFISH : t
val _CKK_TWOFISH : t
val _CKK_SECURID : t
val _CKK_HOTP : t
val _CKK_ACTI : t
val _CKK_CAMELLIA : t
val _CKK_ARIA : t
val _CKK_VENDOR_DEFINED : t

include P11_sigs.PKCS with type t := t and type u := u
