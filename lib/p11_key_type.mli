type t =
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
[@@deriving eq, ord, show, yojson]

val of_string : string -> t

val to_string : t -> string
