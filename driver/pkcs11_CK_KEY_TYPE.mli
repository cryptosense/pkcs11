(** Key types ([CK_KEY_TYPE]) *)

type t = P11_ulong.t

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

val view : t -> P11_key_type.t

val make : P11_key_type.t -> t
