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

type _t
type t = _t structure
let ck_attribute : _t structure typ = structure "CK_ATTRIBUTE"
let (-:) ty label = smart_field ck_attribute label ty
let _type = Pkcs11_CK_ATTRIBUTE_TYPE.typ -: "type"
let pValue = Reachable_ptr.typ void -: "pValue"
let ulValueLen = ulong -: "ulValueLen"
let () = seal ck_attribute

type 'a u = 'a P11_attribute_type.t * 'a

let pack (a, b) = P11_attribute.Pack (a, b)

(** [create cka] allocates a new struct and set the [attribute_type]
    field to [cka]. The value and its length are both initialised to
    default values. *)
let create attribute_type : t =
  let a = Ctypes.make ck_attribute in
  setf a _type attribute_type;
  Reachable_ptr.setf a pValue null;
  setf a ulValueLen (Unsigned.ULong.zero);
  a

(** [allocate t] updates the structure in place by allocating memory
    for the value. *)
let allocate (t: t) : unit =
  let count = Unsigned.ULong.to_int  (getf t ulValueLen) in
  Reachable_ptr.setf t pValue (to_voidp (allocate_n (char) ~count));
  ()

let get_type t =
  getf t _type

let get_length t =
  Unsigned.ULong.to_int (getf t ulValueLen)

let pvalue_is_null_ptr t = is_null (Reachable_ptr.getf t pValue)

let unsafe_get_value typ t =
  from_voidp typ (Reachable_ptr.getf t pValue)

let ck_true : Pkcs11_CK_BBOOL.t ptr = Ctypes.allocate Pkcs11_CK_BBOOL.typ Pkcs11_CK_BBOOL._CK_TRUE
let ck_false : Pkcs11_CK_BBOOL.t ptr = Ctypes.allocate Pkcs11_CK_BBOOL.typ Pkcs11_CK_BBOOL._CK_FALSE

(* Constructors *)

let boolean attribute_type bool : t =
  let a = Ctypes.make ck_attribute in
  let bool = if bool then ck_true else ck_false in
  setf a _type attribute_type;
  Reachable_ptr.setf a pValue (to_voidp bool);
  setf a ulValueLen (Unsigned.ULong.of_int (sizeof uint8_t));
  a

let byte attribute_type byte : t =
  let a = Ctypes.make ck_attribute in
  let byte = Ctypes.allocate Ctypes.uint8_t (Unsigned.UInt8.of_int byte) in
  setf a _type attribute_type;
  Reachable_ptr.setf a pValue (to_voidp byte);
  setf a ulValueLen (Unsigned.ULong.of_int (sizeof uint8_t));
  a

let ulong attribute_type ulong : t =
  let a = Ctypes.make ck_attribute in
  let ulong = Ctypes.allocate Ctypes.ulong ulong in
  setf a _type attribute_type;
  Reachable_ptr.setf a pValue (to_voidp ulong);
  setf a ulValueLen (Unsigned.ULong.of_int (sizeof Ctypes.ulong));
  a

let string attribute_type string : t =
  let a = Ctypes.make ck_attribute in
  let s = ptr_from_string string in
  setf a _type attribute_type;
  Reachable_ptr.setf a pValue (to_voidp s);
  setf a ulValueLen (Unsigned.ULong.of_int (String.length string));
  a

let bigint attr_type u =
  string attr_type (P11_bigint.encode u)

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
  P11_bigint.decode (unsafe_get_string t)

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
    | Ok p -> pack (attr_type, p)
    | Error e ->
        begin
          let open P11_attribute_type in
          let open Pkcs11_CK_ATTRIBUTE_TYPE in
          let name = to_string attr_type in
          Pkcs11_log.log @@ Printf.sprintf "Invalid %s: %S (error: %S)" name s e;
          let code = CKA_CS_UNKNOWN (make attr_type) in
          let value = NOT_IMPLEMENTED s in
          pack (code, value)
        end

let decode_cka_ec_point s =
  decode_cka P11_attribute_type.CKA_EC_POINT decode_ec_point s

let decode_cka_ec_params s =
  decode_cka P11_attribute_type.CKA_EC_PARAMS Key_parsers.Asn1.EC.Params.decode s

let encode_asn grammar x =
  let codec = Asn.codec Asn.der grammar in
  Cstruct.to_string @@ Asn.encode codec x

let encode_ec_params = encode_asn Key_parsers.Asn1.EC.Params.grammar
let encode_ec_point = encode_asn Key_parsers.Asn1.EC.point_grammar

let view t =
  let open P11_attribute_type in
  let open Pkcs11_CK_ATTRIBUTE_TYPE in
  let ul = getf t _type in
  let it_is c =
    Pkcs11_CK_ATTRIBUTE_TYPE.equal ul c
  in
  match () with
  | _ when it_is _CKA_CLASS               -> pack (CKA_CLASS, (unsafe_get_object_class t |> Pkcs11_CK_OBJECT_CLASS.view))
  | _ when it_is _CKA_TOKEN               -> pack (CKA_TOKEN, (unsafe_get_bool t))
  | _ when it_is _CKA_PRIVATE             -> pack (CKA_PRIVATE, (unsafe_get_bool t))
  | _ when it_is _CKA_LABEL               -> pack (CKA_LABEL, (unsafe_get_string t))
  | _ when it_is _CKA_VALUE               -> pack (CKA_VALUE, (unsafe_get_string t))
  | _ when it_is _CKA_TRUSTED             -> pack (CKA_TRUSTED, (unsafe_get_bool t))
  | _ when it_is _CKA_CHECK_VALUE         -> pack (CKA_CHECK_VALUE, NOT_IMPLEMENTED (unsafe_get_string t))
  | _ when it_is _CKA_KEY_TYPE            -> pack (CKA_KEY_TYPE, (unsafe_get_key_type t |> Pkcs11_CK_KEY_TYPE.view))
  | _ when it_is _CKA_SUBJECT             -> pack (CKA_SUBJECT,  (unsafe_get_string t))
  | _ when it_is _CKA_ID                  -> pack (CKA_ID,       (unsafe_get_string t))
  | _ when it_is _CKA_SENSITIVE           -> pack (CKA_SENSITIVE, (unsafe_get_bool t))
  | _ when it_is _CKA_ENCRYPT             -> pack (CKA_ENCRYPT, (unsafe_get_bool t))
  | _ when it_is _CKA_DECRYPT             -> pack (CKA_DECRYPT, (unsafe_get_bool t))
  | _ when it_is _CKA_WRAP                -> pack (CKA_WRAP, (unsafe_get_bool t))
  | _ when it_is _CKA_UNWRAP              -> pack (CKA_UNWRAP, (unsafe_get_bool t))
  | _ when it_is _CKA_SIGN                -> pack (CKA_SIGN, (unsafe_get_bool t))
  | _ when it_is _CKA_SIGN_RECOVER        -> pack (CKA_SIGN_RECOVER, (unsafe_get_bool t))
  | _ when it_is _CKA_VERIFY              -> pack (CKA_VERIFY, (unsafe_get_bool t))
  | _ when it_is _CKA_VERIFY_RECOVER      -> pack (CKA_VERIFY_RECOVER, (unsafe_get_bool t))
  | _ when it_is _CKA_DERIVE              -> pack (CKA_DERIVE, (unsafe_get_bool t))
  | _ when it_is _CKA_START_DATE          -> pack (CKA_START_DATE, NOT_IMPLEMENTED (unsafe_get_string t))
  | _ when it_is _CKA_END_DATE            -> pack (CKA_END_DATE, NOT_IMPLEMENTED (unsafe_get_string t))
  | _ when it_is _CKA_MODULUS             -> pack (CKA_MODULUS, (unsafe_get_bigint t))
  | _ when it_is _CKA_MODULUS_BITS        -> pack (CKA_MODULUS_BITS, (unsafe_get_ulong t))
  | _ when it_is _CKA_PUBLIC_EXPONENT     -> pack (CKA_PUBLIC_EXPONENT, (unsafe_get_bigint t))
  | _ when it_is _CKA_PRIVATE_EXPONENT    -> pack (CKA_PRIVATE_EXPONENT, (unsafe_get_bigint t))
  | _ when it_is _CKA_PRIME_1             -> pack (CKA_PRIME_1, (unsafe_get_bigint t))
  | _ when it_is _CKA_PRIME_2             -> pack (CKA_PRIME_2, (unsafe_get_bigint t))
  | _ when it_is _CKA_EXPONENT_1          -> pack (CKA_EXPONENT_1, (unsafe_get_bigint t))
  | _ when it_is _CKA_EXPONENT_2          -> pack (CKA_EXPONENT_2, (unsafe_get_bigint t))
  | _ when it_is _CKA_COEFFICIENT         -> pack (CKA_COEFFICIENT, (unsafe_get_bigint t))
  | _ when it_is _CKA_PRIME               -> pack (CKA_PRIME, (unsafe_get_bigint t))
  | _ when it_is _CKA_SUBPRIME            -> pack (CKA_SUBPRIME, (unsafe_get_bigint t))
  | _ when it_is _CKA_PRIME_BITS          -> pack (CKA_PRIME_BITS, unsafe_get_ulong t)
  | _ when it_is _CKA_SUBPRIME_BITS       -> pack (CKA_SUBPRIME_BITS, unsafe_get_ulong t)
  | _ when it_is _CKA_VALUE_LEN           -> pack (CKA_VALUE_LEN, (unsafe_get_ulong t))
  | _ when it_is _CKA_EXTRACTABLE         -> pack (CKA_EXTRACTABLE, (unsafe_get_bool t))
  | _ when it_is _CKA_LOCAL               -> pack (CKA_LOCAL, (unsafe_get_bool t))
  | _ when it_is _CKA_NEVER_EXTRACTABLE   -> pack (CKA_NEVER_EXTRACTABLE, (unsafe_get_bool t))
  | _ when it_is _CKA_ALWAYS_SENSITIVE    -> pack (CKA_ALWAYS_SENSITIVE, (unsafe_get_bool t))
  | _ when it_is _CKA_KEY_GEN_MECHANISM   -> pack (CKA_KEY_GEN_MECHANISM, Pkcs11_key_gen_mechanism.view (unsafe_get_ulong t))
  | _ when it_is _CKA_MODIFIABLE          -> pack (CKA_MODIFIABLE, (unsafe_get_bool t))
  | _ when it_is _CKA_EC_PARAMS           -> decode_cka_ec_params (unsafe_get_string t)
  | _ when it_is _CKA_EC_POINT            -> decode_cka_ec_point (unsafe_get_string t)
  | _ when it_is _CKA_ALWAYS_AUTHENTICATE -> pack (CKA_ALWAYS_AUTHENTICATE, (unsafe_get_bool t))
  | _ when it_is _CKA_WRAP_WITH_TRUSTED   -> pack (CKA_WRAP_WITH_TRUSTED,   (unsafe_get_bool t))
  | _ when it_is _CKA_WRAP_TEMPLATE       -> pack (CKA_WRAP_TEMPLATE, NOT_IMPLEMENTED (unsafe_get_string t))
  | _ when it_is _CKA_UNWRAP_TEMPLATE     -> pack (CKA_UNWRAP_TEMPLATE, NOT_IMPLEMENTED (unsafe_get_string t))
  | _ when it_is _CKA_ALLOWED_MECHANISMS  -> pack (CKA_ALLOWED_MECHANISMS, NOT_IMPLEMENTED (unsafe_get_string t))
  | _ ->
    begin
      Pkcs11_log.log @@ Printf.sprintf "Unknown CKA code: 0x%Lx" @@ Int64.of_string @@ Unsigned.ULong.to_string ul;
      pack (CKA_CS_UNKNOWN ul, NOT_IMPLEMENTED (unsafe_get_string t))
    end

let make (type s) (x:s u) =
  let open P11_attribute_type in
  match x with
  | CKA_CLASS, cko -> ulong Pkcs11_CK_ATTRIBUTE_TYPE._CKA_CLASS (Pkcs11_CK_OBJECT_CLASS.make cko)
  | CKA_TOKEN, b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_TOKEN b
  | CKA_PRIVATE, b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_PRIVATE b
  | CKA_LABEL, s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_LABEL s
  | CKA_VALUE, s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_VALUE s
  | CKA_TRUSTED, b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_TRUSTED b
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
  | CKA_PRIME_BITS, ul -> ulong Pkcs11_CK_ATTRIBUTE_TYPE._CKA_PRIME_BITS ul
  | CKA_SUBPRIME_BITS, ul -> ulong Pkcs11_CK_ATTRIBUTE_TYPE._CKA_SUBPRIME_BITS ul
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
  | CKA_ALWAYS_AUTHENTICATE, b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_ALWAYS_AUTHENTICATE b
  | CKA_WRAP_WITH_TRUSTED,   b -> boolean Pkcs11_CK_ATTRIBUTE_TYPE._CKA_WRAP_WITH_TRUSTED   b
  | CKA_WRAP_TEMPLATE, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_WRAP_TEMPLATE s
  | CKA_UNWRAP_TEMPLATE, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_UNWRAP_TEMPLATE s
  | CKA_ALLOWED_MECHANISMS, NOT_IMPLEMENTED s -> string Pkcs11_CK_ATTRIBUTE_TYPE._CKA_ALLOWED_MECHANISMS s
  | CKA_CS_UNKNOWN ul, NOT_IMPLEMENTED s ->
      string ul s

let make_pack (P11_attribute.Pack x) = make x

let compare_types = P11_attribute.compare_types
let compare_types_pack = P11_attribute.compare_types_pack

let compare = P11_attribute.compare

let compare_pack = P11_attribute.compare_pack

let equal = P11_attribute.equal
let equal_pack = P11_attribute.equal_pack
