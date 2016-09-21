(** An attribute is a single parameter of a key template. An
    attribute can hold a Boolean value, a string value, a key type
    value, and so on and so forth. They are pervasively used in the
    PKCS11 API, and are one of the most tricky part of the PKCS11
    interface.

    There are two different use patterns for attributes.

    - The user may set up a list of attribute (e.g., set CKA_TRUSTED to
    true and CKA_ENCRYPT to false) and use this list as input for a
    given function. The list will never be read again by the user.

    - The user may set up a list of attribute types (e.g. CKA_TRUSTED,
    CKA_ENCRYPT, CKA_LABEL) and query the API for the values of these
    attributes. This query is a two step process in which the user first
    set up an array of empty attributes with right type value (the CKA_
    constants). The user make a call to C_GetAttributeValue which sets
    up the correct size for each attribute. Then the user must allocate
    enough memory for each attribute and make another call. At the end
    of this call, each attribute contains the right value.

    We can expose "safe" bindings in the following way. We define
    [Attribute.u] as a variant. The user can use user-friendly templates
    (e.g. lists of Attribute.u) as inputs for functions that do not
    modifiy the templates. We provide a wrapper around functions that
    modifies the templates, so that they take as input a list of
    AttributeType.t (i.e., the manifest constants that are used to
    describe attributes) and they return a list of Attribute.u.
*)

open Ctypes
open Ctypes_helpers
open Result

type _t
type t = _t structure
let ck_attribute : _t structure typ = structure "CK_ATTRIBUTE"
let (-:) ty label = smart_field ck_attribute label ty
let _type = Pkcs11_CK_ATTRIBUTE_TYPE.typ -: "type"
let pValue = Ctypes.ptr void -: "pValue"
let ulValueLen = ulong -: "ulValueLen"
let () = seal ck_attribute

type 'a u = 'a Pkcs11_CK_ATTRIBUTE_TYPE.u * 'a
type pack = Pack : 'a u -> pack

(** [create cka] allocates a new struct and set the [attribute_type]
    field to [cka]. The value and its length are both initialised to
    default values. *)
let create attribute_type : t =
  let a = Ctypes.make ck_attribute in
  setf a _type attribute_type;
  setf a pValue null;
  setf a ulValueLen (Unsigned.ULong.zero);
  a

(** [allocate t] updates the structure in place by allocating memory
    for the value. *)
let allocate (t: t) : unit =
  let count = Unsigned.ULong.to_int  (getf t ulValueLen) in
  setf t pValue (to_voidp (allocate_n (char) ~count));
  ()

let get_type t =
  getf t _type

let get_length t =
  Unsigned.ULong.to_int (getf t ulValueLen)

let pvalue_is_null_ptr t = is_null (getf t pValue)

let unsafe_get_value typ t =
  from_voidp typ (getf t pValue)

let ck_true : Pkcs11_CK_BBOOL.t ptr  = Ctypes.allocate Pkcs11_CK_BBOOL.typ Pkcs11_CK_BBOOL._CK_TRUE
let ck_false : Pkcs11_CK_BBOOL.t ptr = Ctypes.allocate Pkcs11_CK_BBOOL.typ Pkcs11_CK_BBOOL._CK_FALSE

(* Constructors *)

let boolean attribute_type bool : t =
  let a = Ctypes.make ck_attribute in
  let bool = if bool then ck_true else ck_false in
  setf a _type attribute_type;
  setf a pValue (to_voidp bool);
  setf a ulValueLen (Unsigned.ULong.of_int (sizeof uint8_t));
  a

let byte attribute_type byte : t =
  let  a= Ctypes.make ck_attribute in
  let byte = Ctypes.allocate Ctypes.uint8_t (Unsigned.UInt8.of_int byte) in
  setf a _type attribute_type;
  setf a pValue (to_voidp byte);
  setf a ulValueLen (Unsigned.ULong.of_int (sizeof uint8_t));
  a

let ulong attribute_type ulong : t =
  let  a= Ctypes.make ck_attribute in
  let ulong = Ctypes.allocate Ctypes.ulong ulong in
  setf a _type attribute_type;
  setf a pValue (to_voidp ulong);
  setf a ulValueLen (Unsigned.ULong.of_int (sizeof Ctypes.ulong));
  a

let string attribute_type string : t =
  let a = Ctypes.make ck_attribute in
  let s = ptr_from_string string in
  setf a _type attribute_type;
  setf a pValue (to_voidp s);
  setf a ulValueLen (Unsigned.ULong.of_int (String.length string));
  a

let bigint attr_type u =
  string attr_type (Pkcs11_CK_BIGINT.encode u)

(* Accessors *)

let unsafe_get_bool t =
  let p = unsafe_get_value uint8_t t in
  let b = !@ p in
  Unsigned.UInt8.to_int b <> 0

let unsafe_get_byte t =
  let p = unsafe_get_value uint8_t t in
  let b = !@ p in
  Unsigned.UInt8.to_int b

(** [unsafe_get_string] reads the length of the string in [t], so it
    is able to handle string with \000 inside. *)
let unsafe_get_string t =
  let length = get_length t in
  let p  = unsafe_get_value char t in
  string_from_ptr p ~length

let unsafe_get_ulong t =
  let p = unsafe_get_value Ctypes.ulong t in
  !@ p

let unsafe_get_object_class : t -> Pkcs11_CK_OBJECT_CLASS.t =
  unsafe_get_ulong

let unsafe_get_key_type : t -> Pkcs11_CK_KEY_TYPE.t =
  unsafe_get_ulong

let unsafe_get_bigint t =
  Pkcs11_CK_BIGINT.decode (unsafe_get_string t)

let decode_ec_point cs =
  let grammar = Key_parsers.Asn1.EC.point_grammar in
  let codec = Asn.codec Asn.ber grammar in
  match Asn.decode codec cs with
    | None -> Error "Parse error"
    | Some (r, leftover) when Cstruct.len leftover <> 0 ->
        Error ("CKA_EC_POINT: leftover")
    | Some (r, _) -> Ok r

(**
   Pack the specified attribute, but if decoding fails, log the error and return
   an CKA_CS_UNKNOWN attribute.
 *)
let decode_cka attr_type decode s =
  match decode @@ Cstruct.of_string s with
    | Ok p -> Pack (attr_type, p)
    | Error e ->
        begin
          let open Pkcs11_CK_ATTRIBUTE_TYPE in
          let name = to_string attr_type in
          Pkcs11_log.log @@ Printf.sprintf "Invalid %s: %S (error: %S)" name s e;
          let code = CKA_CS_UNKNOWN (make attr_type) in
          let value = NOT_IMPLEMENTED s in
          Pack (code, value)
        end

let decode_cka_ec_point s =
  decode_cka Pkcs11_CK_ATTRIBUTE_TYPE.CKA_EC_POINT decode_ec_point s

let decode_cka_ec_params s =
  decode_cka Pkcs11_CK_ATTRIBUTE_TYPE.CKA_EC_PARAMS Key_parsers.Asn1.EC.Params.decode s

let encode_asn grammar x =
  let codec = Asn.codec Asn.der grammar in
  Cstruct.to_string @@ Asn.encode codec x

let encode_ec_params = encode_asn Key_parsers.Asn1.EC.Params.grammar
let encode_ec_point = encode_asn Key_parsers.Asn1.EC.point_grammar

let view (t : t) : pack =
  let ul = getf t _type in
  let open Pkcs11_CK_ATTRIBUTE_TYPE in
  if ul ==  _CKA_CLASS                              then Pack (CKA_CLASS, (unsafe_get_object_class t |> Pkcs11_CK_OBJECT_CLASS.view))
  else if ul ==  _CKA_TOKEN                         then Pack (CKA_TOKEN, (unsafe_get_bool t))
  else if ul ==  _CKA_PRIVATE                       then Pack (CKA_PRIVATE, (unsafe_get_bool t))
  else if ul ==  _CKA_LABEL                         then Pack (CKA_LABEL, (unsafe_get_string t))
  else if ul ==  _CKA_APPLICATION                   then Pack (CKA_APPLICATION, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_VALUE                         then Pack (CKA_VALUE, (unsafe_get_string t))
  else if ul ==  _CKA_OBJECT_ID                     then Pack (CKA_OBJECT_ID, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_CERTIFICATE_TYPE              then Pack (CKA_CERTIFICATE_TYPE, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_ISSUER                        then Pack (CKA_ISSUER, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_SERIAL_NUMBER                 then Pack (CKA_SERIAL_NUMBER, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_AC_ISSUER                     then Pack (CKA_AC_ISSUER, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_OWNER                         then Pack (CKA_OWNER, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_ATTR_TYPES                    then Pack (CKA_ATTR_TYPES, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_TRUSTED                       then Pack (CKA_TRUSTED, (unsafe_get_bool t))
  else if ul ==  _CKA_CERTIFICATE_CATEGORY          then Pack (CKA_CERTIFICATE_CATEGORY, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_JAVA_MIDP_SECURITY_DOMAIN     then Pack (CKA_JAVA_MIDP_SECURITY_DOMAIN, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_URL                           then Pack (CKA_URL, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_HASH_OF_SUBJECT_PUBLIC_KEY    then Pack (CKA_HASH_OF_SUBJECT_PUBLIC_KEY, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_HASH_OF_ISSUER_PUBLIC_KEY     then Pack (CKA_HASH_OF_ISSUER_PUBLIC_KEY, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_CHECK_VALUE                   then Pack (CKA_CHECK_VALUE, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_KEY_TYPE                      then Pack (CKA_KEY_TYPE, (unsafe_get_key_type t |> Pkcs11_CK_KEY_TYPE.view))
  else if ul ==  _CKA_SUBJECT                       then Pack (CKA_SUBJECT,  (unsafe_get_string t))
  else if ul ==  _CKA_ID                            then Pack (CKA_ID,       (unsafe_get_string t))
  else if ul ==  _CKA_SENSITIVE                     then Pack (CKA_SENSITIVE, (unsafe_get_bool t))
  else if ul ==  _CKA_ENCRYPT                       then Pack (CKA_ENCRYPT, (unsafe_get_bool t))
  else if ul ==  _CKA_DECRYPT                       then Pack (CKA_DECRYPT, (unsafe_get_bool t))
  else if ul ==  _CKA_WRAP                          then Pack (CKA_WRAP, (unsafe_get_bool t))
  else if ul ==  _CKA_UNWRAP                        then Pack (CKA_UNWRAP, (unsafe_get_bool t))
  else if ul ==  _CKA_SIGN                          then Pack (CKA_SIGN, (unsafe_get_bool t))
  else if ul ==  _CKA_SIGN_RECOVER                  then Pack (CKA_SIGN_RECOVER, (unsafe_get_bool t))
  else if ul ==  _CKA_VERIFY                        then Pack (CKA_VERIFY, (unsafe_get_bool t))
  else if ul ==  _CKA_VERIFY_RECOVER                then Pack (CKA_VERIFY_RECOVER, (unsafe_get_bool t))
  else if ul ==  _CKA_DERIVE                        then Pack (CKA_DERIVE, (unsafe_get_bool t))
  else if ul ==  _CKA_START_DATE                    then Pack (CKA_START_DATE, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_END_DATE                      then Pack (CKA_END_DATE, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_MODULUS                       then Pack (CKA_MODULUS, (unsafe_get_bigint t))
  else if ul ==  _CKA_MODULUS_BITS                  then Pack (CKA_MODULUS_BITS, (unsafe_get_ulong t))
  else if ul ==  _CKA_PUBLIC_EXPONENT               then Pack (CKA_PUBLIC_EXPONENT, (unsafe_get_bigint t))
  else if ul ==  _CKA_PRIVATE_EXPONENT              then Pack (CKA_PRIVATE_EXPONENT, (unsafe_get_bigint t))
  else if ul ==  _CKA_PRIME_1                       then Pack (CKA_PRIME_1, (unsafe_get_bigint t))
  else if ul ==  _CKA_PRIME_2                       then Pack (CKA_PRIME_2, (unsafe_get_bigint t))
  else if ul ==  _CKA_EXPONENT_1                    then Pack (CKA_EXPONENT_1, (unsafe_get_bigint t))
  else if ul ==  _CKA_EXPONENT_2                    then Pack (CKA_EXPONENT_2, (unsafe_get_bigint t))
  else if ul ==  _CKA_COEFFICIENT                   then Pack (CKA_COEFFICIENT, (unsafe_get_bigint t))
  else if ul ==  _CKA_PRIME                         then Pack (CKA_PRIME, (unsafe_get_bigint t))
  else if ul ==  _CKA_SUBPRIME                      then Pack (CKA_SUBPRIME, (unsafe_get_bigint t))
  else if ul ==  _CKA_BASE                          then Pack (CKA_BASE, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_PRIME_BITS                    then Pack (CKA_PRIME_BITS, unsafe_get_ulong t)
  else if ul ==  _CKA_SUBPRIME_BITS                 then Pack (CKA_SUBPRIME_BITS, unsafe_get_ulong t)
  (* else if ul ==  _CKA_SUB_PRIME_BITS                then Pack (CKA_SUB_PRIME_BITS, NOT_IMPLEMENTED (unsafe_get_string t)) *)
  else if ul ==  _CKA_VALUE_BITS                    then Pack (CKA_VALUE_BITS, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_VALUE_LEN                     then Pack (CKA_VALUE_LEN, (unsafe_get_ulong t))
  else if ul ==  _CKA_EXTRACTABLE                   then Pack (CKA_EXTRACTABLE, (unsafe_get_bool t))
  else if ul ==  _CKA_LOCAL                         then Pack (CKA_LOCAL, (unsafe_get_bool t))
  else if ul ==  _CKA_NEVER_EXTRACTABLE             then Pack (CKA_NEVER_EXTRACTABLE, (unsafe_get_bool t))
  else if ul ==  _CKA_ALWAYS_SENSITIVE              then Pack (CKA_ALWAYS_SENSITIVE, (unsafe_get_bool t))
  else if ul ==  _CKA_KEY_GEN_MECHANISM             then Pack (CKA_KEY_GEN_MECHANISM, Pkcs11_key_gen_mechanism.view (unsafe_get_ulong t))
  else if ul ==  _CKA_MODIFIABLE                    then Pack (CKA_MODIFIABLE, (unsafe_get_bool t))
  (* else if ul ==  _CKA_ECDSA_PARAMS                  then Pack (CKA_ECDSA_PARAMS, (unsafe_get_string t)) *)
  else if ul ==  _CKA_EC_PARAMS                     then decode_cka_ec_params (unsafe_get_string t)
  else if ul ==  _CKA_EC_POINT                      then decode_cka_ec_point (unsafe_get_string t)
  else if ul ==  _CKA_SECONDARY_AUTH                then Pack (CKA_SECONDARY_AUTH, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_AUTH_PIN_FLAGS                then Pack (CKA_AUTH_PIN_FLAGS, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_ALWAYS_AUTHENTICATE           then Pack (CKA_ALWAYS_AUTHENTICATE, (unsafe_get_bool t))
  else if ul ==  _CKA_WRAP_WITH_TRUSTED             then Pack (CKA_WRAP_WITH_TRUSTED,   (unsafe_get_bool t))
  else if ul ==  _CKA_WRAP_TEMPLATE                 then Pack (CKA_WRAP_TEMPLATE, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_UNWRAP_TEMPLATE               then Pack (CKA_UNWRAP_TEMPLATE, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_OTP_FORMAT                    then Pack (CKA_OTP_FORMAT, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_OTP_LENGTH                    then Pack (CKA_OTP_LENGTH, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_OTP_TIME_INTERVAL             then Pack (CKA_OTP_TIME_INTERVAL, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_OTP_USER_FRIENDLY_MODE        then Pack (CKA_OTP_USER_FRIENDLY_MODE, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_OTP_CHALLENGE_REQUIREMENT     then Pack (CKA_OTP_CHALLENGE_REQUIREMENT, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_OTP_TIME_REQUIREMENT          then Pack (CKA_OTP_TIME_REQUIREMENT, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_OTP_COUNTER_REQUIREMENT       then Pack (CKA_OTP_COUNTER_REQUIREMENT, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_OTP_PIN_REQUIREMENT           then Pack (CKA_OTP_PIN_REQUIREMENT, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_OTP_COUNTER                   then Pack (CKA_OTP_COUNTER, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_OTP_TIME                      then Pack (CKA_OTP_TIME, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_OTP_USER_IDENTIFIER           then Pack (CKA_OTP_USER_IDENTIFIER, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_OTP_SERVICE_IDENTIFIER        then Pack (CKA_OTP_SERVICE_IDENTIFIER, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_OTP_SERVICE_LOGO              then Pack (CKA_OTP_SERVICE_LOGO, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_OTP_SERVICE_LOGO_TYPE         then Pack (CKA_OTP_SERVICE_LOGO_TYPE, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_HW_FEATURE_TYPE               then Pack (CKA_HW_FEATURE_TYPE, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_RESET_ON_INIT                 then Pack (CKA_RESET_ON_INIT, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_HAS_RESET                     then Pack (CKA_HAS_RESET, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_PIXEL_X                       then Pack (CKA_PIXEL_X, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_PIXEL_Y                       then Pack (CKA_PIXEL_Y, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_RESOLUTION                    then Pack (CKA_RESOLUTION, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_CHAR_ROWS                     then Pack (CKA_CHAR_ROWS, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_CHAR_COLUMNS                  then Pack (CKA_CHAR_COLUMNS, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_COLOR                         then Pack (CKA_COLOR, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_BITS_PER_PIXEL                then Pack (CKA_BITS_PER_PIXEL, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_CHAR_SETS                     then Pack (CKA_CHAR_SETS, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_ENCODING_METHODS              then Pack (CKA_ENCODING_METHODS, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_MIME_TYPES                    then Pack (CKA_MIME_TYPES, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_MECHANISM_TYPE                then Pack (CKA_MECHANISM_TYPE, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_REQUIRED_CMS_ATTRIBUTES       then Pack (CKA_REQUIRED_CMS_ATTRIBUTES, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_DEFAULT_CMS_ATTRIBUTES        then Pack (CKA_DEFAULT_CMS_ATTRIBUTES, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_SUPPORTED_CMS_ATTRIBUTES      then Pack (CKA_SUPPORTED_CMS_ATTRIBUTES, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_ALLOWED_MECHANISMS            then Pack (CKA_ALLOWED_MECHANISMS, NOT_IMPLEMENTED (unsafe_get_string t))
  else if ul ==  _CKA_VENDOR_DEFINED                then Pack (CKA_VENDOR_DEFINED, NOT_IMPLEMENTED (unsafe_get_string t))
  else
    begin
      Pkcs11_log.log @@ Printf.sprintf "Unknown CKA code: 0x%Lx" @@ Int64.of_string @@ Unsigned.ULong.to_string ul;
      Pack (CKA_CS_UNKNOWN ul, NOT_IMPLEMENTED (unsafe_get_string t))
    end

(* Useful regexp |\(.*\) of string -> | \1 s -> string AttributesType.\1 s): *)

let make : type s . s u -> t = fun x ->
  let open Pkcs11_CK_ATTRIBUTE_TYPE in
  match x with
  | CKA_CLASS, cko -> ulong Pkcs11_CK_ATTRIBUTE_TYPE._CKA_CLASS (Pkcs11_CK_OBJECT_CLASS.make cko)
  | CKA_TOKEN, b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_TOKEN b
  | CKA_PRIVATE, b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_PRIVATE b
  | CKA_LABEL, s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_LABEL s
  | CKA_APPLICATION, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_APPLICATION s
  | CKA_VALUE, s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_VALUE s
  | CKA_OBJECT_ID, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_OBJECT_ID s
  | CKA_CERTIFICATE_TYPE, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_CERTIFICATE_TYPE s
  | CKA_ISSUER, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_ISSUER s
  | CKA_SERIAL_NUMBER, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_SERIAL_NUMBER s
  | CKA_AC_ISSUER, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_AC_ISSUER s
  | CKA_OWNER, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_OWNER s
  | CKA_ATTR_TYPES, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_ATTR_TYPES s
  | CKA_TRUSTED, b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_TRUSTED b
  | CKA_CERTIFICATE_CATEGORY, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_CERTIFICATE_CATEGORY s
  | CKA_JAVA_MIDP_SECURITY_DOMAIN, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_JAVA_MIDP_SECURITY_DOMAIN s
  | CKA_URL, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_URL s
  | CKA_HASH_OF_SUBJECT_PUBLIC_KEY, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_HASH_OF_SUBJECT_PUBLIC_KEY s
  | CKA_HASH_OF_ISSUER_PUBLIC_KEY, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_HASH_OF_ISSUER_PUBLIC_KEY s
  | CKA_CHECK_VALUE, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_CHECK_VALUE s
  | CKA_KEY_TYPE, ckk -> ulong Pkcs11_CK_ATTRIBUTE_TYPE._CKA_KEY_TYPE (Pkcs11_CK_KEY_TYPE.make ckk)
  | CKA_SUBJECT, s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_SUBJECT s
  | CKA_ID, s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_ID s
  | CKA_SENSITIVE, b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_SENSITIVE b
  | CKA_ENCRYPT,   b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_ENCRYPT   b
  | CKA_DECRYPT,   b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_DECRYPT   b
  | CKA_WRAP, b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_WRAP b
  | CKA_UNWRAP, b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_UNWRAP b
  | CKA_SIGN, b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_SIGN b
  | CKA_SIGN_RECOVER, b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_SIGN_RECOVER b
  | CKA_VERIFY, b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_VERIFY b
  | CKA_VERIFY_RECOVER, b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_VERIFY_RECOVER b
  | CKA_DERIVE, b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_DERIVE b
  | CKA_START_DATE, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_START_DATE s
  | CKA_END_DATE, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_END_DATE s
  | CKA_MODULUS, n -> bigint Pkcs11_CK_ATTRIBUTE_TYPE._CKA_MODULUS n
  | CKA_MODULUS_BITS,     ul -> ulong Pkcs11_CK_ATTRIBUTE_TYPE._CKA_MODULUS_BITS     ul
  | CKA_PUBLIC_EXPONENT, n -> bigint Pkcs11_CK_ATTRIBUTE_TYPE._CKA_PUBLIC_EXPONENT n
  | CKA_PRIVATE_EXPONENT, n -> bigint Pkcs11_CK_ATTRIBUTE_TYPE._CKA_PRIVATE_EXPONENT n
  | CKA_PRIME_1, n -> bigint Pkcs11_CK_ATTRIBUTE_TYPE._CKA_PRIME_1 n
  | CKA_PRIME_2, n -> bigint Pkcs11_CK_ATTRIBUTE_TYPE._CKA_PRIME_2 n
  | CKA_EXPONENT_1, n -> bigint Pkcs11_CK_ATTRIBUTE_TYPE._CKA_EXPONENT_1 n
  | CKA_EXPONENT_2, n -> bigint Pkcs11_CK_ATTRIBUTE_TYPE._CKA_EXPONENT_2 n
  | CKA_COEFFICIENT, n -> bigint Pkcs11_CK_ATTRIBUTE_TYPE._CKA_COEFFICIENT n
  | CKA_PRIME, n -> bigint Pkcs11_CK_ATTRIBUTE_TYPE._CKA_PRIME n
  | CKA_SUBPRIME, n -> bigint Pkcs11_CK_ATTRIBUTE_TYPE._CKA_SUBPRIME n
  | CKA_BASE, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_BASE s
  | CKA_PRIME_BITS, ul -> ulong Pkcs11_CK_ATTRIBUTE_TYPE._CKA_PRIME_BITS ul
  | CKA_SUBPRIME_BITS, ul -> ulong Pkcs11_CK_ATTRIBUTE_TYPE._CKA_SUBPRIME_BITS ul
  (* | CKA_SUB_PRIME_BITS, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_SUB_PRIME_BITS s *)
  | CKA_VALUE_BITS, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_VALUE_BITS s
  | CKA_VALUE_LEN, ul -> ulong Pkcs11_CK_ATTRIBUTE_TYPE._CKA_VALUE_LEN ul
  | CKA_EXTRACTABLE, b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_EXTRACTABLE b
  | CKA_LOCAL,  b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_LOCAL  b
  | CKA_NEVER_EXTRACTABLE, b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_NEVER_EXTRACTABLE b
  | CKA_ALWAYS_SENSITIVE, b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_ALWAYS_SENSITIVE b
  | CKA_KEY_GEN_MECHANISM, m ->
      Pkcs11_key_gen_mechanism.make m
      |> ulong Pkcs11_CK_ATTRIBUTE_TYPE._CKA_KEY_GEN_MECHANISM
  | CKA_MODIFIABLE, b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_MODIFIABLE b
  (* | CKA_ECDSA_PARAMS, s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_ECDSA_PARAMS s *)
  | CKA_EC_PARAMS, p ->
      encode_ec_params p |> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_EC_PARAMS
  | CKA_EC_POINT, p -> encode_ec_point p |> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_EC_POINT
  | CKA_SECONDARY_AUTH, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_SECONDARY_AUTH s
  | CKA_AUTH_PIN_FLAGS, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_AUTH_PIN_FLAGS s
  | CKA_ALWAYS_AUTHENTICATE, b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_ALWAYS_AUTHENTICATE b
  | CKA_WRAP_WITH_TRUSTED,   b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_WRAP_WITH_TRUSTED   b
  | CKA_WRAP_TEMPLATE, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_WRAP_TEMPLATE s
  | CKA_UNWRAP_TEMPLATE, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_UNWRAP_TEMPLATE s
  | CKA_OTP_FORMAT, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_OTP_FORMAT s
  | CKA_OTP_LENGTH, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_OTP_LENGTH s
  | CKA_OTP_TIME_INTERVAL, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_OTP_TIME_INTERVAL s
  | CKA_OTP_USER_FRIENDLY_MODE, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_OTP_USER_FRIENDLY_MODE s
  | CKA_OTP_CHALLENGE_REQUIREMENT, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_OTP_CHALLENGE_REQUIREMENT s
  | CKA_OTP_TIME_REQUIREMENT, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_OTP_TIME_REQUIREMENT s
  | CKA_OTP_COUNTER_REQUIREMENT, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_OTP_COUNTER_REQUIREMENT s
  | CKA_OTP_PIN_REQUIREMENT, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_OTP_PIN_REQUIREMENT s
  | CKA_OTP_COUNTER, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_OTP_COUNTER s
  | CKA_OTP_TIME, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_OTP_TIME s
  | CKA_OTP_USER_IDENTIFIER, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_OTP_USER_IDENTIFIER s
  | CKA_OTP_SERVICE_IDENTIFIER, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_OTP_SERVICE_IDENTIFIER s
  | CKA_OTP_SERVICE_LOGO, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_OTP_SERVICE_LOGO s
  | CKA_OTP_SERVICE_LOGO_TYPE, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_OTP_SERVICE_LOGO_TYPE s
  | CKA_HW_FEATURE_TYPE, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_HW_FEATURE_TYPE s
  | CKA_RESET_ON_INIT, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_RESET_ON_INIT s
  | CKA_HAS_RESET, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_HAS_RESET s
  | CKA_PIXEL_X, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_PIXEL_X s
  | CKA_PIXEL_Y, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_PIXEL_Y s
  | CKA_RESOLUTION, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_RESOLUTION s
  | CKA_CHAR_ROWS, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_CHAR_ROWS s
  | CKA_CHAR_COLUMNS, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_CHAR_COLUMNS s
  | CKA_COLOR, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_COLOR s
  | CKA_BITS_PER_PIXEL, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_BITS_PER_PIXEL s
  | CKA_CHAR_SETS, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_CHAR_SETS s
  | CKA_ENCODING_METHODS, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_ENCODING_METHODS s
  | CKA_MIME_TYPES, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_MIME_TYPES s
  | CKA_MECHANISM_TYPE, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_MECHANISM_TYPE s
  | CKA_REQUIRED_CMS_ATTRIBUTES, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_REQUIRED_CMS_ATTRIBUTES s
  | CKA_DEFAULT_CMS_ATTRIBUTES, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_DEFAULT_CMS_ATTRIBUTES s
  | CKA_SUPPORTED_CMS_ATTRIBUTES, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_SUPPORTED_CMS_ATTRIBUTES s
  | CKA_ALLOWED_MECHANISMS, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_ALLOWED_MECHANISMS s
  | CKA_VENDOR_DEFINED, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_VENDOR_DEFINED s
  | CKA_CS_UNKNOWN ul, NOT_IMPLEMENTED s ->
      string ul s

let make_pack (Pack x) = make x

let to_string_pair =
  let ulong cka x = cka, Unsigned.ULong.to_string x in
  let object_class cka cko = cka, Pkcs11_CK_OBJECT_CLASS.to_string cko in
  let bool cka x = cka, if x then "CK_TRUE" else "CK_FALSE" in
  let string cka x = cka, Printf.sprintf "%S" x in
  let key_type cka ckk = cka, Pkcs11_CK_KEY_TYPE.to_string ckk in
  let mechanism_type cka x = cka, Pkcs11_key_gen_mechanism.to_string x in
  let ec_parameters cka x = cka, Key_parsers.Asn1.EC.Params.show x in
  let ec_point cka x = cka, Key_parsers.Asn1.EC.show_point x in
  let bigint cka x = cka, Pkcs11_CK_BIGINT.to_string x in
  fun (type s) (x : s u) ->
    let open Pkcs11_CK_ATTRIBUTE_TYPE in
    match x with
      | CKA_CLASS, x               -> object_class "CKA_CLASS" x
      | CKA_TOKEN, x               -> bool "CKA_TOKEN" x
      | CKA_PRIVATE, x             -> bool "CKA_PRIVATE" x
      | CKA_LABEL, x               -> string "CKA_LABEL" x
      | CKA_APPLICATION, NOT_IMPLEMENTED x -> string "CKA_APPLICATION" x
      | CKA_VALUE, x               -> string "CKA_VALUE" x
      | CKA_OBJECT_ID, NOT_IMPLEMENTED x -> string "CKA_OBJECT_ID" x
      | CKA_CERTIFICATE_TYPE, NOT_IMPLEMENTED x -> string "CKA_CERTIFICATE_TYPE" x
      | CKA_ISSUER, NOT_IMPLEMENTED x -> string "CKA_ISSUER" x
      | CKA_SERIAL_NUMBER, NOT_IMPLEMENTED x -> string "CKA_SERIAL_NUMBER" x
      | CKA_AC_ISSUER, NOT_IMPLEMENTED x -> string "CKA_AC_ISSUER" x
      | CKA_OWNER, NOT_IMPLEMENTED x -> string "CKA_OWNER" x
      | CKA_ATTR_TYPES, NOT_IMPLEMENTED x -> string "CKA_ATTR_TYPES" x
      | CKA_TRUSTED, x             -> bool "CKA_TRUSTED" x
      | CKA_CERTIFICATE_CATEGORY, NOT_IMPLEMENTED x -> string "CKA_CERTIFICATE_CATEGORY" x
      | CKA_JAVA_MIDP_SECURITY_DOMAIN, NOT_IMPLEMENTED x -> string "CKA_JAVA_MIDP_SECURITY_DOMAIN" x
      | CKA_URL, NOT_IMPLEMENTED x -> string "CKA_URL" x
      | CKA_HASH_OF_SUBJECT_PUBLIC_KEY, NOT_IMPLEMENTED x -> string "CKA_HASH_OF_SUBJECT_PUBLIC_KEY" x
      | CKA_HASH_OF_ISSUER_PUBLIC_KEY, NOT_IMPLEMENTED x -> string "CKA_HASH_OF_ISSUER_PUBLIC_KEY" x
      | CKA_CHECK_VALUE, NOT_IMPLEMENTED x -> string "CKA_CHECK_VALUE" x
      | CKA_KEY_TYPE, x            -> key_type "CKA_KEY_TYPE" x
      | CKA_SUBJECT, x             -> string "CKA_SUBJECT" x
      | CKA_ID, x                  -> string "CKA_ID" x
      | CKA_SENSITIVE, x           -> bool "CKA_SENSITIVE" x
      | CKA_ENCRYPT,   x           -> bool "CKA_ENCRYPT" x
      | CKA_DECRYPT,   x           -> bool "CKA_DECRYPT" x
      | CKA_WRAP, x                -> bool "CKA_WRAP" x
      | CKA_UNWRAP, x              -> bool "CKA_UNWRAP" x
      | CKA_SIGN, x                -> bool "CKA_SIGN" x
      | CKA_SIGN_RECOVER, x        -> bool "CKA_SIGN_RECOVER" x
      | CKA_VERIFY, x              -> bool "CKA_VERIFY" x
      | CKA_VERIFY_RECOVER, x      -> bool "CKA_VERIFY_RECOVER" x
      | CKA_DERIVE, x              -> bool "CKA_DERIVE" x
      | CKA_START_DATE, NOT_IMPLEMENTED x -> string "CKA_START_DATE" x
      | CKA_END_DATE, NOT_IMPLEMENTED x -> string "CKA_END_DATE" x
      | CKA_MODULUS,  x            -> bigint "CKA_MODULUS" x
      | CKA_MODULUS_BITS,     x    -> ulong "CKA_MODULUS_BITS" x
      | CKA_PUBLIC_EXPONENT,  x    -> bigint "CKA_PUBLIC_EXPONENT" x
      | CKA_PRIVATE_EXPONENT, x    -> bigint "CKA_PRIVATE_EXPONENT" x
      | CKA_PRIME_1,          x    -> bigint "CKA_PRIME_1" x
      | CKA_PRIME_2,          x    -> bigint "CKA_PRIME_2" x
      | CKA_EXPONENT_1,       x    -> bigint "CKA_EXPONENT_1" x
      | CKA_EXPONENT_2,       x    -> bigint "CKA_EXPONENT_2" x
      | CKA_COEFFICIENT,      x    -> bigint "CKA_COEFFICIENT" x
      | CKA_PRIME,            x    -> bigint "CKA_PRIME" x
      | CKA_SUBPRIME,         x    -> bigint "CKA_SUBPRIME" x
      | CKA_BASE, NOT_IMPLEMENTED x -> string "CKA_BASE" x
      | CKA_PRIME_BITS,  x          -> ulong "CKA_PRIME_BITS" x
      | CKA_SUBPRIME_BITS, x        -> ulong "CKA_SUBPRIME_BITS" x
      (* | CKA_SUB_PRIME_BITS, NOT_IMPLEMENTED x -> string "CKA_SUB_PRIME_BITS" x *)
      | CKA_VALUE_BITS, NOT_IMPLEMENTED x -> string "CKA_VALUE_BITS" x
      | CKA_VALUE_LEN, x           -> ulong "CKA_VALUE_LEN" x
      | CKA_EXTRACTABLE, x         -> bool "CKA_EXTRACTABLE" x
      | CKA_LOCAL,  x              -> bool "CKA_LOCAL" x
      | CKA_NEVER_EXTRACTABLE, x   -> bool "CKA_NEVER_EXTRACTABLE" x
      | CKA_ALWAYS_SENSITIVE, x    -> bool "CKA_ALWAYS_SENSITIVE" x
      | CKA_KEY_GEN_MECHANISM, x   -> mechanism_type "CKA_KEY_GEN_MECHANISM" x
      | CKA_MODIFIABLE, x          -> bool "CKA_MODIFIABLE" x
      (* | CKA_ECDSA_PARAMS, x        -> string "CKA_ECDSA_PARAMS" x *)
      | CKA_EC_PARAMS, x           -> ec_parameters "CKA_EC_PARAMS" x
      | CKA_EC_POINT, x            -> ec_point "CKA_EC_POINT" x
      | CKA_SECONDARY_AUTH, NOT_IMPLEMENTED x -> string "CKA_SECONDARY_AUTH" x
      | CKA_AUTH_PIN_FLAGS, NOT_IMPLEMENTED x -> string "CKA_AUTH_PIN_FLAGS" x
      | CKA_ALWAYS_AUTHENTICATE, x -> bool "CKA_ALWAYS_AUTHENTICATE" x
      | CKA_WRAP_WITH_TRUSTED,   x -> bool "CKA_WRAP_WITH_TRUSTED" x
      | CKA_WRAP_TEMPLATE, NOT_IMPLEMENTED x -> string "CKA_WRAP_TEMPLATE" x
      | CKA_UNWRAP_TEMPLATE, NOT_IMPLEMENTED x -> string "CKA_UNWRAP_TEMPLATE" x
      | CKA_OTP_FORMAT, NOT_IMPLEMENTED x -> string "CKA_OTP_FORMAT" x
      | CKA_OTP_LENGTH, NOT_IMPLEMENTED x -> string "CKA_OTP_LENGTH" x
      | CKA_OTP_TIME_INTERVAL, NOT_IMPLEMENTED x -> string "CKA_OTP_TIME_INTERVAL" x
      | CKA_OTP_USER_FRIENDLY_MODE, NOT_IMPLEMENTED x -> string "CKA_OTP_USER_FRIENDLY_MODE" x
      | CKA_OTP_CHALLENGE_REQUIREMENT, NOT_IMPLEMENTED x -> string "CKA_OTP_CHALLENGE_REQUIREMENT" x
      | CKA_OTP_TIME_REQUIREMENT, NOT_IMPLEMENTED x -> string "CKA_OTP_TIME_REQUIREMENT" x
      | CKA_OTP_COUNTER_REQUIREMENT, NOT_IMPLEMENTED x -> string "CKA_OTP_COUNTER_REQUIREMENT" x
      | CKA_OTP_PIN_REQUIREMENT, NOT_IMPLEMENTED x -> string "CKA_OTP_PIN_REQUIREMENT" x
      | CKA_OTP_COUNTER, NOT_IMPLEMENTED x -> string "CKA_OTP_COUNTER" x
      | CKA_OTP_TIME, NOT_IMPLEMENTED x -> string "CKA_OTP_TIME" x
      | CKA_OTP_USER_IDENTIFIER, NOT_IMPLEMENTED x -> string "CKA_OTP_USER_IDENTIFIER" x
      | CKA_OTP_SERVICE_IDENTIFIER, NOT_IMPLEMENTED x -> string "CKA_OTP_SERVICE_IDENTIFIER" x
      | CKA_OTP_SERVICE_LOGO, NOT_IMPLEMENTED x -> string "CKA_OTP_SERVICE_LOGO" x
      | CKA_OTP_SERVICE_LOGO_TYPE, NOT_IMPLEMENTED x -> string "CKA_OTP_SERVICE_LOGO_TYPE" x
      | CKA_HW_FEATURE_TYPE, NOT_IMPLEMENTED x -> string "CKA_HW_FEATURE_TYPE" x
      | CKA_RESET_ON_INIT, NOT_IMPLEMENTED x -> string "CKA_RESET_ON_INIT" x
      | CKA_HAS_RESET, NOT_IMPLEMENTED x -> string "CKA_HAS_RESET" x
      | CKA_PIXEL_X, NOT_IMPLEMENTED x -> string "CKA_PIXEL_X" x
      | CKA_PIXEL_Y, NOT_IMPLEMENTED x -> string "CKA_PIXEL_Y" x
      | CKA_RESOLUTION, NOT_IMPLEMENTED x -> string "CKA_RESOLUTION" x
      | CKA_CHAR_ROWS, NOT_IMPLEMENTED x -> string "CKA_CHAR_ROWS" x
      | CKA_CHAR_COLUMNS, NOT_IMPLEMENTED x -> string "CKA_CHAR_COLUMNS" x
      | CKA_COLOR, NOT_IMPLEMENTED x -> string "CKA_COLOR" x
      | CKA_BITS_PER_PIXEL, NOT_IMPLEMENTED x -> string "CKA_BITS_PER_PIXEL" x
      | CKA_CHAR_SETS, NOT_IMPLEMENTED x -> string "CKA_CHAR_SETS" x
      | CKA_ENCODING_METHODS, NOT_IMPLEMENTED x -> string "CKA_ENCODING_METHODS" x
      | CKA_MIME_TYPES, NOT_IMPLEMENTED x -> string "CKA_MIME_TYPES" x
      | CKA_MECHANISM_TYPE, NOT_IMPLEMENTED x -> string "CKA_MECHANISM_TYPE" x
      | CKA_REQUIRED_CMS_ATTRIBUTES, NOT_IMPLEMENTED x -> string "CKA_REQUIRED_CMS_ATTRIBUTES" x
      | CKA_DEFAULT_CMS_ATTRIBUTES, NOT_IMPLEMENTED x -> string "CKA_DEFAULT_CMS_ATTRIBUTES" x
      | CKA_SUPPORTED_CMS_ATTRIBUTES, NOT_IMPLEMENTED x -> string "CKA_SUPPORTED_CMS_ATTRIBUTES" x
      | CKA_ALLOWED_MECHANISMS, NOT_IMPLEMENTED x -> string "CKA_ALLOWED_MECHANISMS" x
      | CKA_VENDOR_DEFINED, NOT_IMPLEMENTED x -> string "CKA_VENDOR_DEFINED" x
      | CKA_CS_UNKNOWN ul, NOT_IMPLEMENTED x -> string (Unsigned.ULong.to_string ul) x

let to_string x =
  let a, b = to_string_pair x in
  Printf.sprintf "%s %s" a b

let compare_types (a,_) (b,_) =
  Pkcs11_CK_ATTRIBUTE_TYPE.compare a b

let compare_types_pack (Pack(a,_)) (Pack(b,_)) = Pkcs11_CK_ATTRIBUTE_TYPE.compare a b

let compare_bool (x : bool) (y : bool) = compare x y
let compare_string (x : string) (y : string) = compare x y
let compare_ulong = Unsigned.ULong.compare
let compare : type a b. a u -> b u -> int = fun a b ->
  let open Pkcs11_CK_ATTRIBUTE_TYPE in
  let c = compare_types a b in
  if c <> 0 then
    c
  else
    (* This match raises warning 4 in a spurious manner. The first
       component of the match would be non-exhaustive if we added a
       new constructor to the the type. The system is not smart
       enough to detect that the right part (which would become
       non-exhaustive) is related to the left part. *)
    match[@ocaml.warning "-4"] a, b with
      | (CKA_CLASS, a_param), (CKA_CLASS, b_param) ->
          Pkcs11_CK_OBJECT_CLASS.compare a_param b_param
      | (CKA_KEY_TYPE, a_param), (CKA_KEY_TYPE, b_param) ->
          Pkcs11_CK_KEY_TYPE.compare a_param b_param
      | (CKA_MODULUS_BITS, a_param), (CKA_MODULUS_BITS, b_param) ->
          Pkcs11_CK_ULONG.compare a_param b_param
      | (CKA_VALUE_LEN, a_param), (CKA_VALUE_LEN, b_param) ->
          Pkcs11_CK_ULONG.compare a_param b_param
      | (CKA_KEY_GEN_MECHANISM, a_param), (CKA_KEY_GEN_MECHANISM, b_param) ->
          Pkcs11_key_gen_mechanism.compare a_param b_param
      | (CKA_EC_PARAMS, a_param), (CKA_EC_PARAMS, b_param) ->
          Key_parsers.Asn1.EC.Params.compare a_param b_param
      | (CKA_EC_POINT, a_param), (CKA_EC_POINT, b_param) ->
          Key_parsers.Asn1.EC.compare_point a_param b_param
      | (CKA_PUBLIC_EXPONENT, a_param), (CKA_PUBLIC_EXPONENT, b_param) -> Pkcs11_CK_BIGINT.compare a_param b_param
      | (CKA_PRIVATE_EXPONENT, a_param), (CKA_PRIVATE_EXPONENT, b_param) -> Pkcs11_CK_BIGINT.compare a_param b_param
      | (CKA_PRIME_1, a_param), (CKA_PRIME_1, b_param) -> Pkcs11_CK_BIGINT.compare a_param b_param
      | (CKA_PRIME_2, a_param), (CKA_PRIME_2, b_param) -> Pkcs11_CK_BIGINT.compare a_param b_param
      | (CKA_EXPONENT_1, a_param), (CKA_EXPONENT_1, b_param) -> Pkcs11_CK_BIGINT.compare a_param b_param
      | (CKA_EXPONENT_2, a_param), (CKA_EXPONENT_2, b_param) -> Pkcs11_CK_BIGINT.compare a_param b_param
      | (CKA_COEFFICIENT, a_param), (CKA_COEFFICIENT, b_param) -> Pkcs11_CK_BIGINT.compare a_param b_param
      | (CKA_PRIME, a_param), (CKA_PRIME, b_param) -> Pkcs11_CK_BIGINT.compare a_param b_param
      | (CKA_SUBPRIME, a_param), (CKA_SUBPRIME, b_param) -> Pkcs11_CK_BIGINT.compare a_param b_param
      | (CKA_MODULUS, a_param), (CKA_MODULUS, b_param) -> Pkcs11_CK_BIGINT.compare a_param b_param

      | (CKA_TOKEN, a_param), (CKA_TOKEN, b_param) -> compare_bool a_param b_param
      | (CKA_PRIVATE, a_param), (CKA_PRIVATE, b_param) -> compare_bool a_param b_param
      | (CKA_TRUSTED, a_param), (CKA_TRUSTED, b_param) -> compare_bool a_param b_param
      | (CKA_SENSITIVE, a_param), (CKA_SENSITIVE, b_param) -> compare_bool a_param b_param
      | (CKA_ENCRYPT, a_param), (CKA_ENCRYPT, b_param) -> compare_bool a_param b_param
      | (CKA_DECRYPT, a_param), (CKA_DECRYPT, b_param) -> compare_bool a_param b_param
      | (CKA_WRAP, a_param), (CKA_WRAP, b_param) -> compare_bool a_param b_param
      | (CKA_UNWRAP, a_param), (CKA_UNWRAP, b_param) -> compare_bool a_param b_param
      | (CKA_SIGN, a_param), (CKA_SIGN, b_param) -> compare_bool a_param b_param
      | (CKA_SIGN_RECOVER, a_param), (CKA_SIGN_RECOVER, b_param) -> compare_bool a_param b_param
      | (CKA_VERIFY, a_param), (CKA_VERIFY, b_param) -> compare_bool a_param b_param
      | (CKA_VERIFY_RECOVER, a_param), (CKA_VERIFY_RECOVER, b_param) -> compare_bool a_param b_param
      | (CKA_DERIVE, a_param), (CKA_DERIVE, b_param) -> compare_bool a_param b_param
      | (CKA_EXTRACTABLE, a_param), (CKA_EXTRACTABLE, b_param) -> compare_bool a_param b_param
      | (CKA_LOCAL, a_param), (CKA_LOCAL, b_param) -> compare_bool a_param b_param
      | (CKA_NEVER_EXTRACTABLE, a_param), (CKA_NEVER_EXTRACTABLE, b_param) -> compare_bool a_param b_param
      | (CKA_ALWAYS_SENSITIVE, a_param), (CKA_ALWAYS_SENSITIVE, b_param) -> compare_bool a_param b_param
      | (CKA_MODIFIABLE, a_param), (CKA_MODIFIABLE, b_param) -> compare_bool a_param b_param
      | (CKA_ALWAYS_AUTHENTICATE, a_param), (CKA_ALWAYS_AUTHENTICATE, b_param) -> compare_bool a_param b_param
      | (CKA_WRAP_WITH_TRUSTED, a_param), (CKA_WRAP_WITH_TRUSTED, b_param) -> compare_bool a_param b_param

      | (CKA_LABEL, a_param), (CKA_LABEL, b_param) -> compare_string a_param b_param
      | (CKA_VALUE, a_param), (CKA_VALUE, b_param) -> compare_string a_param b_param
      | (CKA_SUBJECT, a_param), (CKA_SUBJECT, b_param) -> compare_string a_param b_param
      | (CKA_ID, a_param), (CKA_ID, b_param) -> compare_string a_param b_param

      | (CKA_APPLICATION, NOT_IMPLEMENTED a_param), (CKA_APPLICATION, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_OBJECT_ID, NOT_IMPLEMENTED a_param), (CKA_OBJECT_ID, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_CERTIFICATE_TYPE, NOT_IMPLEMENTED a_param), (CKA_CERTIFICATE_TYPE, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_ISSUER, NOT_IMPLEMENTED a_param), (CKA_ISSUER, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_SERIAL_NUMBER, NOT_IMPLEMENTED a_param), (CKA_SERIAL_NUMBER, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_AC_ISSUER, NOT_IMPLEMENTED a_param), (CKA_AC_ISSUER, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_OWNER, NOT_IMPLEMENTED a_param), (CKA_OWNER, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_ATTR_TYPES, NOT_IMPLEMENTED a_param), (CKA_ATTR_TYPES, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_CERTIFICATE_CATEGORY, NOT_IMPLEMENTED a_param), (CKA_CERTIFICATE_CATEGORY, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_JAVA_MIDP_SECURITY_DOMAIN, NOT_IMPLEMENTED a_param), (CKA_JAVA_MIDP_SECURITY_DOMAIN, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_URL, NOT_IMPLEMENTED a_param), (CKA_URL, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_HASH_OF_SUBJECT_PUBLIC_KEY, NOT_IMPLEMENTED a_param), (CKA_HASH_OF_SUBJECT_PUBLIC_KEY, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_HASH_OF_ISSUER_PUBLIC_KEY, NOT_IMPLEMENTED a_param), (CKA_HASH_OF_ISSUER_PUBLIC_KEY, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_CHECK_VALUE, NOT_IMPLEMENTED a_param), (CKA_CHECK_VALUE, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_START_DATE, NOT_IMPLEMENTED a_param), (CKA_START_DATE, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_END_DATE, NOT_IMPLEMENTED a_param), (CKA_END_DATE, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_BASE, NOT_IMPLEMENTED a_param), (CKA_BASE, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_PRIME_BITS, a_param), (CKA_PRIME_BITS,  b_param) -> compare_ulong a_param b_param
      | (CKA_SUBPRIME_BITS, a_param), (CKA_SUBPRIME_BITS, b_param) -> compare_ulong a_param b_param
      (* | (CKA_SUB_PRIME_BITS, NOT_IMPLEMENTED a_param), (CKA_SUB_PRIME_BITS, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param *)
      | (CKA_VALUE_BITS, NOT_IMPLEMENTED a_param), (CKA_VALUE_BITS, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_SECONDARY_AUTH, NOT_IMPLEMENTED a_param), (CKA_SECONDARY_AUTH, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_AUTH_PIN_FLAGS, NOT_IMPLEMENTED a_param), (CKA_AUTH_PIN_FLAGS, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_WRAP_TEMPLATE, NOT_IMPLEMENTED a_param), (CKA_WRAP_TEMPLATE, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_UNWRAP_TEMPLATE, NOT_IMPLEMENTED a_param), (CKA_UNWRAP_TEMPLATE, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_OTP_FORMAT, NOT_IMPLEMENTED a_param), (CKA_OTP_FORMAT, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_OTP_LENGTH, NOT_IMPLEMENTED a_param), (CKA_OTP_LENGTH, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_OTP_TIME_INTERVAL, NOT_IMPLEMENTED a_param), (CKA_OTP_TIME_INTERVAL, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_OTP_USER_FRIENDLY_MODE, NOT_IMPLEMENTED a_param), (CKA_OTP_USER_FRIENDLY_MODE, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_OTP_CHALLENGE_REQUIREMENT, NOT_IMPLEMENTED a_param), (CKA_OTP_CHALLENGE_REQUIREMENT, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_OTP_TIME_REQUIREMENT, NOT_IMPLEMENTED a_param), (CKA_OTP_TIME_REQUIREMENT, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_OTP_COUNTER_REQUIREMENT, NOT_IMPLEMENTED a_param), (CKA_OTP_COUNTER_REQUIREMENT, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_OTP_PIN_REQUIREMENT, NOT_IMPLEMENTED a_param), (CKA_OTP_PIN_REQUIREMENT, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_OTP_COUNTER, NOT_IMPLEMENTED a_param), (CKA_OTP_COUNTER, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_OTP_TIME, NOT_IMPLEMENTED a_param), (CKA_OTP_TIME, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_OTP_USER_IDENTIFIER, NOT_IMPLEMENTED a_param), (CKA_OTP_USER_IDENTIFIER, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_OTP_SERVICE_IDENTIFIER, NOT_IMPLEMENTED a_param), (CKA_OTP_SERVICE_IDENTIFIER, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_OTP_SERVICE_LOGO, NOT_IMPLEMENTED a_param), (CKA_OTP_SERVICE_LOGO, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_OTP_SERVICE_LOGO_TYPE, NOT_IMPLEMENTED a_param), (CKA_OTP_SERVICE_LOGO_TYPE, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_HW_FEATURE_TYPE, NOT_IMPLEMENTED a_param), (CKA_HW_FEATURE_TYPE, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_RESET_ON_INIT, NOT_IMPLEMENTED a_param), (CKA_RESET_ON_INIT, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_HAS_RESET, NOT_IMPLEMENTED a_param), (CKA_HAS_RESET, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_PIXEL_X, NOT_IMPLEMENTED a_param), (CKA_PIXEL_X, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_PIXEL_Y, NOT_IMPLEMENTED a_param), (CKA_PIXEL_Y, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_RESOLUTION, NOT_IMPLEMENTED a_param), (CKA_RESOLUTION, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_CHAR_ROWS, NOT_IMPLEMENTED a_param), (CKA_CHAR_ROWS, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_CHAR_COLUMNS, NOT_IMPLEMENTED a_param), (CKA_CHAR_COLUMNS, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_COLOR, NOT_IMPLEMENTED a_param), (CKA_COLOR, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_BITS_PER_PIXEL, NOT_IMPLEMENTED a_param), (CKA_BITS_PER_PIXEL, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_CHAR_SETS, NOT_IMPLEMENTED a_param), (CKA_CHAR_SETS, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_ENCODING_METHODS, NOT_IMPLEMENTED a_param), (CKA_ENCODING_METHODS, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_MIME_TYPES, NOT_IMPLEMENTED a_param), (CKA_MIME_TYPES, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_MECHANISM_TYPE, NOT_IMPLEMENTED a_param), (CKA_MECHANISM_TYPE, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_REQUIRED_CMS_ATTRIBUTES, NOT_IMPLEMENTED a_param), (CKA_REQUIRED_CMS_ATTRIBUTES, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_DEFAULT_CMS_ATTRIBUTES, NOT_IMPLEMENTED a_param), (CKA_DEFAULT_CMS_ATTRIBUTES, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_SUPPORTED_CMS_ATTRIBUTES, NOT_IMPLEMENTED a_param), (CKA_SUPPORTED_CMS_ATTRIBUTES, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_ALLOWED_MECHANISMS, NOT_IMPLEMENTED a_param), (CKA_ALLOWED_MECHANISMS, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_VENDOR_DEFINED, NOT_IMPLEMENTED a_param), (CKA_VENDOR_DEFINED, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_CS_UNKNOWN a_ul, NOT_IMPLEMENTED a_param),
        (CKA_CS_UNKNOWN b_ul, NOT_IMPLEMENTED b_param) ->
          let cmp = Unsigned.ULong.compare a_ul b_ul in
          if cmp = 0
          then compare_string a_param b_param
          else cmp
        (* Should have been covered by the comparison of attribute types,
           or by the above cases. *)
      | (CKA_CLASS, _), _ -> assert false
      | (CKA_KEY_TYPE, _), _ -> assert false
      | (CKA_MODULUS_BITS, _), _ -> assert false
      | (CKA_VALUE_LEN, _), _ -> assert false
      | (CKA_KEY_GEN_MECHANISM, _), _ -> assert false
      | (CKA_TOKEN, _), _ -> assert false
      | (CKA_PRIVATE, _), _ -> assert false
      | (CKA_TRUSTED, _), _ -> assert false
      | (CKA_SENSITIVE, _), _ -> assert false
      | (CKA_ENCRYPT, _), _ -> assert false
      | (CKA_DECRYPT, _), _ -> assert false
      | (CKA_WRAP, _), _ -> assert false
      | (CKA_UNWRAP, _), _ -> assert false
      | (CKA_SIGN, _), _ -> assert false
      | (CKA_SIGN_RECOVER, _), _ -> assert false
      | (CKA_VERIFY, _), _ -> assert false
      | (CKA_VERIFY_RECOVER, _), _ -> assert false
      | (CKA_DERIVE, _), _ -> assert false
      | (CKA_EXTRACTABLE, _), _ -> assert false
      | (CKA_LOCAL, _), _ -> assert false
      | (CKA_NEVER_EXTRACTABLE, _), _ -> assert false
      | (CKA_ALWAYS_SENSITIVE, _), _ -> assert false
      | (CKA_MODIFIABLE, _), _ -> assert false
      | (CKA_ALWAYS_AUTHENTICATE, _), _ -> assert false
      | (CKA_WRAP_WITH_TRUSTED, _), _ -> assert false
      | (CKA_LABEL, _), _ -> assert false
      | (CKA_VALUE, _), _ -> assert false
      | (CKA_SUBJECT, _), _ -> assert false
      | (CKA_ID, _), _ -> assert false
      | (CKA_MODULUS, _), _ -> assert false
      | (CKA_PUBLIC_EXPONENT, _), _ -> assert false
      | (CKA_PRIVATE_EXPONENT, _), _ -> assert false
      | (CKA_PRIME_1, _), _ -> assert false
      | (CKA_PRIME_2, _), _ -> assert false
      | (CKA_EXPONENT_1, _), _ -> assert false
      | (CKA_EXPONENT_2, _), _ -> assert false
      | (CKA_COEFFICIENT, _), _ -> assert false
      | (CKA_PRIME, _), _ -> assert false
      | (CKA_SUBPRIME, _), _ -> assert false
      (* | (CKA_ECDSA_PARAMS, _), _ -> assert false *)
      | (CKA_EC_PARAMS, _), _ -> assert false
      | (CKA_EC_POINT, _), _ -> assert false
      | (CKA_APPLICATION, _), _ -> assert false
      | (CKA_OBJECT_ID, _), _ -> assert false
      | (CKA_CERTIFICATE_TYPE, _), _ -> assert false
      | (CKA_ISSUER, _), _ -> assert false
      | (CKA_SERIAL_NUMBER, _), _ -> assert false
      | (CKA_AC_ISSUER, _), _ -> assert false
      | (CKA_OWNER, _), _ -> assert false
      | (CKA_ATTR_TYPES, _), _ -> assert false
      | (CKA_CERTIFICATE_CATEGORY, _), _ -> assert false
      | (CKA_JAVA_MIDP_SECURITY_DOMAIN, _), _ -> assert false
      | (CKA_URL, _), _ -> assert false
      | (CKA_HASH_OF_SUBJECT_PUBLIC_KEY, _), _ -> assert false
      | (CKA_HASH_OF_ISSUER_PUBLIC_KEY, _), _ -> assert false
      | (CKA_CHECK_VALUE, _), _ -> assert false
      | (CKA_START_DATE, _), _ -> assert false
      | (CKA_END_DATE, _), _ -> assert false
      | (CKA_BASE, _), _ -> assert false
      | (CKA_PRIME_BITS, _), _ -> assert false
      | (CKA_SUBPRIME_BITS, _), _ -> assert false
      (* | (CKA_SUB_PRIME_BITS, _), _ -> assert false *)
      | (CKA_VALUE_BITS, _), _ -> assert false
      | (CKA_SECONDARY_AUTH, _), _ -> assert false
      | (CKA_AUTH_PIN_FLAGS, _), _ -> assert false
      | (CKA_WRAP_TEMPLATE, _), _ -> assert false
      | (CKA_UNWRAP_TEMPLATE, _), _ -> assert false
      | (CKA_OTP_FORMAT, _), _ -> assert false
      | (CKA_OTP_LENGTH, _), _ -> assert false
      | (CKA_OTP_TIME_INTERVAL, _), _ -> assert false
      | (CKA_OTP_USER_FRIENDLY_MODE, _), _ -> assert false
      | (CKA_OTP_CHALLENGE_REQUIREMENT, _), _ -> assert false
      | (CKA_OTP_TIME_REQUIREMENT, _), _ -> assert false
      | (CKA_OTP_COUNTER_REQUIREMENT, _), _ -> assert false
      | (CKA_OTP_PIN_REQUIREMENT, _), _ -> assert false
      | (CKA_OTP_COUNTER, _), _ -> assert false
      | (CKA_OTP_TIME, _), _ -> assert false
      | (CKA_OTP_USER_IDENTIFIER, _), _ -> assert false
      | (CKA_OTP_SERVICE_IDENTIFIER, _), _ -> assert false
      | (CKA_OTP_SERVICE_LOGO, _), _ -> assert false
      | (CKA_OTP_SERVICE_LOGO_TYPE, _), _ -> assert false
      | (CKA_HW_FEATURE_TYPE, _), _ -> assert false
      | (CKA_RESET_ON_INIT, _), _ -> assert false
      | (CKA_HAS_RESET, _), _ -> assert false
      | (CKA_PIXEL_X, _), _ -> assert false
      | (CKA_PIXEL_Y, _), _ -> assert false
      | (CKA_RESOLUTION, _), _ -> assert false
      | (CKA_CHAR_ROWS, _), _ -> assert false
      | (CKA_CHAR_COLUMNS, _), _ -> assert false
      | (CKA_COLOR, _), _ -> assert false
      | (CKA_BITS_PER_PIXEL, _), _ -> assert false
      | (CKA_CHAR_SETS, _), _ -> assert false
      | (CKA_ENCODING_METHODS, _), _ -> assert false
      | (CKA_MIME_TYPES, _), _ -> assert false
      | (CKA_MECHANISM_TYPE, _), _ -> assert false
      | (CKA_REQUIRED_CMS_ATTRIBUTES, _), _ -> assert false
      | (CKA_DEFAULT_CMS_ATTRIBUTES, _), _ -> assert false
      | (CKA_SUPPORTED_CMS_ATTRIBUTES, _), _ -> assert false
      | (CKA_ALLOWED_MECHANISMS, _), _ -> assert false
      | (CKA_VENDOR_DEFINED, _), _ -> assert false
      | (CKA_CS_UNKNOWN _, _), _ -> assert false

let compare_pack (Pack a) (Pack b) = compare a b

let equal a b =
  compare a b = 0

let equal_pack (Pack a) (Pack b) = equal a b
