open Ctypes

include P11_attribute_type.Encoding

type t = Pkcs11_CK_ULONG.t
[@@deriving ord]

let view (ul : t) : P11_attribute_type.pack =
  let open P11_attribute_type in
  let (==) = P11_attribute_type.(==) in
  if ul ==  _CKA_CLASS                              then Pack CKA_CLASS
  else if ul ==  _CKA_TOKEN                         then Pack CKA_TOKEN
  else if ul ==  _CKA_PRIVATE                       then Pack CKA_PRIVATE
  else if ul ==  _CKA_LABEL                         then Pack CKA_LABEL
  else if ul ==  _CKA_VALUE                         then Pack CKA_VALUE
  else if ul ==  _CKA_TRUSTED                       then Pack CKA_TRUSTED
  else if ul ==  _CKA_CHECK_VALUE                   then Pack CKA_CHECK_VALUE
  else if ul ==  _CKA_KEY_TYPE                      then Pack CKA_KEY_TYPE
  else if ul ==  _CKA_SUBJECT                       then Pack CKA_SUBJECT
  else if ul ==  _CKA_ID                            then Pack CKA_ID
  else if ul ==  _CKA_SENSITIVE                     then Pack CKA_SENSITIVE
  else if ul ==  _CKA_ENCRYPT                       then Pack CKA_ENCRYPT
  else if ul ==  _CKA_DECRYPT                       then Pack CKA_DECRYPT
  else if ul ==  _CKA_WRAP                          then Pack CKA_WRAP
  else if ul ==  _CKA_UNWRAP                        then Pack CKA_UNWRAP
  else if ul ==  _CKA_SIGN                          then Pack CKA_SIGN
  else if ul ==  _CKA_SIGN_RECOVER                  then Pack CKA_SIGN_RECOVER
  else if ul ==  _CKA_VERIFY                        then Pack CKA_VERIFY
  else if ul ==  _CKA_VERIFY_RECOVER                then Pack CKA_VERIFY_RECOVER
  else if ul ==  _CKA_DERIVE                        then Pack CKA_DERIVE
  else if ul ==  _CKA_START_DATE                    then Pack CKA_START_DATE
  else if ul ==  _CKA_END_DATE                      then Pack CKA_END_DATE
  else if ul ==  _CKA_MODULUS                       then Pack CKA_MODULUS
  else if ul ==  _CKA_MODULUS_BITS                  then Pack CKA_MODULUS_BITS
  else if ul ==  _CKA_PUBLIC_EXPONENT               then Pack CKA_PUBLIC_EXPONENT
  else if ul ==  _CKA_PRIVATE_EXPONENT              then Pack CKA_PRIVATE_EXPONENT
  else if ul ==  _CKA_PRIME_1                       then Pack CKA_PRIME_1
  else if ul ==  _CKA_PRIME_2                       then Pack CKA_PRIME_2
  else if ul ==  _CKA_EXPONENT_1                    then Pack CKA_EXPONENT_1
  else if ul ==  _CKA_EXPONENT_2                    then Pack CKA_EXPONENT_2
  else if ul ==  _CKA_COEFFICIENT                   then Pack CKA_COEFFICIENT
  else if ul ==  _CKA_PRIME                         then Pack CKA_PRIME
  else if ul ==  _CKA_SUBPRIME                      then Pack CKA_SUBPRIME
  else if ul ==  _CKA_PRIME_BITS                    then Pack CKA_PRIME_BITS
  else if ul ==  _CKA_SUBPRIME_BITS                 then Pack CKA_SUBPRIME_BITS
  else if ul ==  _CKA_VALUE_LEN                     then Pack CKA_VALUE_LEN
  else if ul ==  _CKA_EXTRACTABLE                   then Pack CKA_EXTRACTABLE
  else if ul ==  _CKA_LOCAL                         then Pack CKA_LOCAL
  else if ul ==  _CKA_NEVER_EXTRACTABLE             then Pack CKA_NEVER_EXTRACTABLE
  else if ul ==  _CKA_ALWAYS_SENSITIVE              then Pack CKA_ALWAYS_SENSITIVE
  else if ul ==  _CKA_KEY_GEN_MECHANISM             then Pack CKA_KEY_GEN_MECHANISM
  else if ul ==  _CKA_MODIFIABLE                    then Pack CKA_MODIFIABLE
  else if ul ==  _CKA_EC_PARAMS                     then Pack CKA_EC_PARAMS
  else if ul ==  _CKA_EC_POINT                      then Pack CKA_EC_POINT
  else if ul ==  _CKA_ALWAYS_AUTHENTICATE           then Pack CKA_ALWAYS_AUTHENTICATE
  else if ul ==  _CKA_WRAP_WITH_TRUSTED             then Pack CKA_WRAP_WITH_TRUSTED
  else if ul ==  _CKA_WRAP_TEMPLATE                 then Pack CKA_WRAP_TEMPLATE
  else if ul ==  _CKA_UNWRAP_TEMPLATE               then Pack CKA_UNWRAP_TEMPLATE
  else if ul ==  _CKA_ALLOWED_MECHANISMS            then Pack CKA_ALLOWED_MECHANISMS
  else
    begin
      Pkcs11_log.log @@ Printf.sprintf "Unknown CKA code: 0x%Lx" @@ Int64.of_string @@ Unsigned.ULong.to_string ul;
      Pack (CKA_CS_UNKNOWN ul)
    end

let typ = ulong
