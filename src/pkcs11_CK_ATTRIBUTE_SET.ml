open Ctypes
open Pkcs11_CK_ATTRIBUTE

let _setter_ : (unit Ctypes.ptr -> 'a -> unit) -> Unsigned.ULong.t -> t -> 'a -> Pkcs11_CK_RV.u =
  fun ff size t elem ->
    if pvalue_is_null_ptr t
    then
      begin
        setf t ulValueLen size;
        Pkcs11_CK_RV.CKR_OK
      end
    else
      begin
        if getf t ulValueLen >= size
        then
          begin
            ff (getf t pValue) elem;
            setf t ulValueLen size;
            Pkcs11_CK_RV.CKR_OK
          end
        else
          begin
            setf t ulValueLen Unsigned.ULong.max_int;
            Pkcs11_CK_RV.CKR_BUFFER_TOO_SMALL
          end
      end

let _setter typ converter = _setter_ (fun ptr elem -> Ctypes.from_voidp typ ptr <-@ (converter elem))

let boolean =
  _setter
    Pkcs11_CK_BBOOL.typ
    (function true -> Pkcs11_CK_BBOOL._CK_TRUE | false -> Pkcs11_CK_BBOOL._CK_FALSE)
    (Unsigned.ULong.of_int (sizeof uint8_t))

let byte =
  _setter
    Ctypes.uint8_t
    Unsigned.UInt8.of_int
    (Unsigned.ULong.of_int (sizeof uint8_t))

let ulong =
  _setter
    Ctypes.ulong
    (fun x -> x)
    (Unsigned.ULong.of_int (sizeof Ctypes.ulong))

let key_gen_mechanism =
  _setter
    Ctypes.ulong
    Pkcs11_key_gen_mechanism.make
    (Unsigned.ULong.of_int (sizeof Ctypes.ulong))

let string t elem =
  _setter_
    (fun p s ->
       let ptr = Ctypes.from_voidp (Ctypes.char) p in
       String.iteri (fun i c -> (ptr +@ i) <-@ c) s
    )
    (Unsigned.ULong.of_int (String.length elem))
    t
    elem

let bigint t elem = string t (Pkcs11_CK_BIGINT.encode elem)

let set_access_error t = setf t ulValueLen Unsigned.ULong.max_int

let update (Pack x) t =
  let open Pkcs11_CK_ATTRIBUTE_TYPE in
  match x with
    | CKA_CLASS, cko -> ulong t (Pkcs11_CK_OBJECT_CLASS.make cko)
    | CKA_TOKEN, b -> boolean t b
    | CKA_PRIVATE, b -> boolean t b
    | CKA_LABEL, s -> string t s
    | CKA_APPLICATION, not_implemented -> assert false
    | CKA_VALUE, s -> string t s
    | CKA_OBJECT_ID, not_implemented -> assert false
    | CKA_CERTIFICATE_TYPE, not_implemented -> assert false
    | CKA_ISSUER, not_implemented -> assert false
    | CKA_SERIAL_NUMBER, not_implemented -> assert false
    | CKA_AC_ISSUER, not_implemented -> assert false
    | CKA_OWNER, not_implemented -> assert false
    | CKA_ATTR_TYPES, not_implemented -> assert false
    | CKA_TRUSTED, b -> boolean t b
    | CKA_CERTIFICATE_CATEGORY, not_implemented -> assert false
    | CKA_JAVA_MIDP_SECURITY_DOMAIN, not_implemented -> assert false
    | CKA_URL, not_implemented -> assert false
    | CKA_HASH_OF_SUBJECT_PUBLIC_KEY, not_implemented -> assert false
    | CKA_HASH_OF_ISSUER_PUBLIC_KEY, not_implemented -> assert false
    | CKA_CHECK_VALUE, not_implemented -> assert false
    | CKA_KEY_TYPE, ckk -> ulong t (Pkcs11_CK_KEY_TYPE.make ckk)
    | CKA_SUBJECT, s -> string t s
    | CKA_ID, s -> string t s
    | CKA_SENSITIVE, b -> boolean t b
    | CKA_ENCRYPT,   b -> boolean t b
    | CKA_DECRYPT,   b -> boolean t b
    | CKA_WRAP, b -> boolean t b
    | CKA_UNWRAP, b -> boolean t b
    | CKA_SIGN, b -> boolean t b
    | CKA_SIGN_RECOVER, b -> boolean t b
    | CKA_VERIFY, b -> boolean t b
    | CKA_VERIFY_RECOVER, b -> boolean t b
    | CKA_DERIVE, b -> boolean t b
    | CKA_START_DATE, not_implemented -> assert false
    | CKA_END_DATE, not_implemented -> assert false
    | CKA_MODULUS, n -> bigint t n
    | CKA_MODULUS_BITS,     ul -> ulong t ul
    | CKA_PUBLIC_EXPONENT, n -> bigint t n
    | CKA_PRIVATE_EXPONENT, n -> bigint t n
    | CKA_PRIME_1, n -> bigint t n
    | CKA_PRIME_2, n -> bigint t n
    | CKA_EXPONENT_1, n -> bigint t n
    | CKA_EXPONENT_2, n -> bigint t n
    | CKA_COEFFICIENT, n -> bigint t n
    | CKA_PRIME, n -> bigint t n
    | CKA_SUBPRIME, n -> bigint t n
    | CKA_BASE, not_implemented -> assert false
    | CKA_PRIME_BITS, not_implemented -> assert false
    | CKA_SUBPRIME_BITS, not_implemented -> assert false
    | CKA_VALUE_BITS, not_implemented -> assert false
    | CKA_VALUE_LEN, ul -> ulong t ul
    | CKA_EXTRACTABLE, b -> boolean t b
    | CKA_LOCAL,  b -> boolean t b
    | CKA_NEVER_EXTRACTABLE, b -> boolean t b
    | CKA_ALWAYS_SENSITIVE, b -> boolean t b
    | CKA_KEY_GEN_MECHANISM, m -> key_gen_mechanism t m
    | CKA_MODIFIABLE, b -> boolean t b
    | CKA_EC_PARAMS, s -> assert false
    | CKA_EC_POINT, s -> assert false
    | CKA_SECONDARY_AUTH, not_implemented -> assert false
    | CKA_AUTH_PIN_FLAGS, not_implemented -> assert false
    | CKA_ALWAYS_AUTHENTICATE, b -> boolean t b
    | CKA_WRAP_WITH_TRUSTED,   b -> boolean t b
    | CKA_WRAP_TEMPLATE, not_implemented -> assert false
    | CKA_UNWRAP_TEMPLATE, not_implemented -> assert false
    | CKA_OTP_FORMAT, not_implemented -> assert false
    | CKA_OTP_LENGTH, not_implemented -> assert false
    | CKA_OTP_TIME_INTERVAL, not_implemented -> assert false
    | CKA_OTP_USER_FRIENDLY_MODE, not_implemented -> assert false
    | CKA_OTP_CHALLENGE_REQUIREMENT, not_implemented -> assert false
    | CKA_OTP_TIME_REQUIREMENT, not_implemented -> assert false
    | CKA_OTP_COUNTER_REQUIREMENT, not_implemented -> assert false
    | CKA_OTP_PIN_REQUIREMENT, not_implemented -> assert false
    | CKA_OTP_COUNTER, not_implemented -> assert false
    | CKA_OTP_TIME, not_implemented -> assert false
    | CKA_OTP_USER_IDENTIFIER, not_implemented -> assert false
    | CKA_OTP_SERVICE_IDENTIFIER, not_implemented -> assert false
    | CKA_OTP_SERVICE_LOGO, not_implemented -> assert false
    | CKA_OTP_SERVICE_LOGO_TYPE, not_implemented -> assert false
    | CKA_HW_FEATURE_TYPE, not_implemented -> assert false
    | CKA_RESET_ON_INIT, not_implemented -> assert false
    | CKA_HAS_RESET, not_implemented -> assert false
    | CKA_PIXEL_X, not_implemented -> assert false
    | CKA_PIXEL_Y, not_implemented -> assert false
    | CKA_RESOLUTION, not_implemented -> assert false
    | CKA_CHAR_ROWS, not_implemented -> assert false
    | CKA_CHAR_COLUMNS, not_implemented -> assert false
    | CKA_COLOR, not_implemented -> assert false
    | CKA_BITS_PER_PIXEL, not_implemented -> assert false
    | CKA_CHAR_SETS, not_implemented -> assert false
    | CKA_ENCODING_METHODS, not_implemented -> assert false
    | CKA_MIME_TYPES, not_implemented -> assert false
    | CKA_MECHANISM_TYPE, not_implemented -> assert false
    | CKA_REQUIRED_CMS_ATTRIBUTES, not_implemented -> assert false
    | CKA_DEFAULT_CMS_ATTRIBUTES, not_implemented -> assert false
    | CKA_SUPPORTED_CMS_ATTRIBUTES, not_implemented -> assert false
    | CKA_ALLOWED_MECHANISMS, not_implemented -> assert false
    | CKA_VENDOR_DEFINED, not_implemented -> assert false
    | CKA_CS_UNKNOWN _, _ -> assert false
