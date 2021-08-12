open Ctypes
include P11_attribute_type.Encoding

type t = P11_ulong.t [@@deriving eq, ord]

let view (ul : t) : P11_attribute_type.pack =
  let it_is c = equal ul c in
  let open P11_attribute_type in
  match () with
  | _ when it_is _CKA_CLASS -> Pack CKA_CLASS
  | _ when it_is _CKA_TOKEN -> Pack CKA_TOKEN
  | _ when it_is _CKA_PRIVATE -> Pack CKA_PRIVATE
  | _ when it_is _CKA_LABEL -> Pack CKA_LABEL
  | _ when it_is _CKA_VALUE -> Pack CKA_VALUE
  | _ when it_is _CKA_TRUSTED -> Pack CKA_TRUSTED
  | _ when it_is _CKA_CHECK_VALUE -> Pack CKA_CHECK_VALUE
  | _ when it_is _CKA_KEY_TYPE -> Pack CKA_KEY_TYPE
  | _ when it_is _CKA_SUBJECT -> Pack CKA_SUBJECT
  | _ when it_is _CKA_ID -> Pack CKA_ID
  | _ when it_is _CKA_SENSITIVE -> Pack CKA_SENSITIVE
  | _ when it_is _CKA_ENCRYPT -> Pack CKA_ENCRYPT
  | _ when it_is _CKA_DECRYPT -> Pack CKA_DECRYPT
  | _ when it_is _CKA_WRAP -> Pack CKA_WRAP
  | _ when it_is _CKA_UNWRAP -> Pack CKA_UNWRAP
  | _ when it_is _CKA_SIGN -> Pack CKA_SIGN
  | _ when it_is _CKA_SIGN_RECOVER -> Pack CKA_SIGN_RECOVER
  | _ when it_is _CKA_VERIFY -> Pack CKA_VERIFY
  | _ when it_is _CKA_VERIFY_RECOVER -> Pack CKA_VERIFY_RECOVER
  | _ when it_is _CKA_DERIVE -> Pack CKA_DERIVE
  | _ when it_is _CKA_START_DATE -> Pack CKA_START_DATE
  | _ when it_is _CKA_END_DATE -> Pack CKA_END_DATE
  | _ when it_is _CKA_MODULUS -> Pack CKA_MODULUS
  | _ when it_is _CKA_MODULUS_BITS -> Pack CKA_MODULUS_BITS
  | _ when it_is _CKA_PUBLIC_EXPONENT -> Pack CKA_PUBLIC_EXPONENT
  | _ when it_is _CKA_PRIVATE_EXPONENT -> Pack CKA_PRIVATE_EXPONENT
  | _ when it_is _CKA_PRIME_1 -> Pack CKA_PRIME_1
  | _ when it_is _CKA_PRIME_2 -> Pack CKA_PRIME_2
  | _ when it_is _CKA_EXPONENT_1 -> Pack CKA_EXPONENT_1
  | _ when it_is _CKA_EXPONENT_2 -> Pack CKA_EXPONENT_2
  | _ when it_is _CKA_COEFFICIENT -> Pack CKA_COEFFICIENT
  | _ when it_is _CKA_PRIME -> Pack CKA_PRIME
  | _ when it_is _CKA_SUBPRIME -> Pack CKA_SUBPRIME
  | _ when it_is _CKA_BASE -> Pack CKA_BASE
  | _ when it_is _CKA_PRIME_BITS -> Pack CKA_PRIME_BITS
  | _ when it_is _CKA_SUBPRIME_BITS -> Pack CKA_SUBPRIME_BITS
  | _ when it_is _CKA_VALUE_LEN -> Pack CKA_VALUE_LEN
  | _ when it_is _CKA_EXTRACTABLE -> Pack CKA_EXTRACTABLE
  | _ when it_is _CKA_LOCAL -> Pack CKA_LOCAL
  | _ when it_is _CKA_NEVER_EXTRACTABLE -> Pack CKA_NEVER_EXTRACTABLE
  | _ when it_is _CKA_ALWAYS_SENSITIVE -> Pack CKA_ALWAYS_SENSITIVE
  | _ when it_is _CKA_KEY_GEN_MECHANISM -> Pack CKA_KEY_GEN_MECHANISM
  | _ when it_is _CKA_MODIFIABLE -> Pack CKA_MODIFIABLE
  | _ when it_is _CKA_EC_PARAMS -> Pack CKA_EC_PARAMS
  | _ when it_is _CKA_EC_POINT -> Pack CKA_EC_POINT
  | _ when it_is _CKA_ALWAYS_AUTHENTICATE -> Pack CKA_ALWAYS_AUTHENTICATE
  | _ when it_is _CKA_WRAP_WITH_TRUSTED -> Pack CKA_WRAP_WITH_TRUSTED
  | _ when it_is _CKA_WRAP_TEMPLATE -> Pack CKA_WRAP_TEMPLATE
  | _ when it_is _CKA_UNWRAP_TEMPLATE -> Pack CKA_UNWRAP_TEMPLATE
  | _ when it_is _CKA_ALLOWED_MECHANISMS -> Pack CKA_ALLOWED_MECHANISMS
  | _ ->
    Pkcs11_log.log
    @@ Printf.sprintf "Unknown CKA code: 0x%Lx"
    @@ Int64.of_string
    @@ Unsigned.ULong.to_string ul;
    Pack (CKA_CS_UNKNOWN ul)

let typ = ulong
