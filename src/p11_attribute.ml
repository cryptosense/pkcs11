type 'a t = 'a P11_attribute_type.t * 'a

type pack = Pack : 'a t -> pack

let to_string_pair =
  let ulong cka x = cka, Unsigned.ULong.to_string x in
  let object_class cka cko = cka, P11_object_class.to_string cko in
  let bool cka x = cka, if x then "CK_TRUE" else "CK_FALSE" in
  let string cka x = cka, Printf.sprintf "%S" x in
  let key_type cka ckk = cka, P11_key_type.to_string ckk in
  let mechanism_type cka x = cka, P11_key_gen_mechanism.to_string x in
  let ec_parameters cka x = cka, Key_parsers.Asn1.EC.Params.show x in
  let ec_point cka x = cka, Key_parsers.Asn1.EC.show_point x in
  let bigint cka x = cka, P11_bigint.to_string x in
  fun (type s) (x : s t) ->
    let open P11_attribute_type in
    match x with
      | CKA_CLASS, x               -> object_class "CKA_CLASS" x
      | CKA_TOKEN, x               -> bool "CKA_TOKEN" x
      | CKA_PRIVATE, x             -> bool "CKA_PRIVATE" x
      | CKA_LABEL, x               -> string "CKA_LABEL" x
      | CKA_VALUE, x               -> string "CKA_VALUE" x
      | CKA_TRUSTED, x             -> bool "CKA_TRUSTED" x
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
      | CKA_PRIME_BITS,  x          -> ulong "CKA_PRIME_BITS" x
      | CKA_SUBPRIME_BITS, x        -> ulong "CKA_SUBPRIME_BITS" x
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
      | CKA_ALWAYS_AUTHENTICATE, x -> bool "CKA_ALWAYS_AUTHENTICATE" x
      | CKA_WRAP_WITH_TRUSTED,   x -> bool "CKA_WRAP_WITH_TRUSTED" x
      | CKA_WRAP_TEMPLATE, NOT_IMPLEMENTED x -> string "CKA_WRAP_TEMPLATE" x
      | CKA_UNWRAP_TEMPLATE, NOT_IMPLEMENTED x -> string "CKA_UNWRAP_TEMPLATE" x
      | CKA_ALLOWED_MECHANISMS, NOT_IMPLEMENTED x -> string "CKA_ALLOWED_MECHANISMS" x
      | CKA_CS_UNKNOWN ul, NOT_IMPLEMENTED x -> string (Unsigned.ULong.to_string ul) x

let to_string x =
  let a, b = to_string_pair x in
  Printf.sprintf "%s %s" a b

(* Note: it is important for [Template.to_json] and [Template.of_json]
   that all attributes are represented using [`Assoc]. *)
let to_json : type a . a t -> Yojson.Safe.json = fun attribute ->
  let open P11_attribute_type in
  let p json_of_param name param =
    `Assoc [ name, json_of_param param ]
  in
  let p_object_class = p P11_object_class.to_yojson in
  let p_bool : string -> bool -> Yojson.Safe.json =
    p @@ fun b -> `String (if b then "CK_TRUE" else "CK_FALSE") in
  let p_string : string -> string -> Yojson.Safe.json =
    p @@ fun s -> `String s in
  let p_data = p P11_hex_data.to_yojson in
  let p_key_type = p P11_key_type.to_yojson in
  let p_ulong = p P11_ulong.to_yojson in
  let p_bigint = p P11_bigint.to_yojson in
  let p_mechanism_type = p P11_key_gen_mechanism.to_yojson in
  let p_ec_params = p Key_parsers.Asn1.EC.Params.to_yojson in
  let p_ec_point = p (fun cs -> P11_hex_data.to_yojson @@ Cstruct.to_string cs)
  in
  match attribute with
    | CKA_CLASS, param ->
        p_object_class "CKA_CLASS" param
    | CKA_TOKEN, param ->
        p_bool "CKA_TOKEN" param
    | CKA_PRIVATE, param ->
        p_bool "CKA_PRIVATE" param
    | CKA_LABEL, param ->
        p_string "CKA_LABEL" param
    | CKA_VALUE, param ->
        p_data "CKA_VALUE" param
    | CKA_TRUSTED, param ->
        p_bool "CKA_TRUSTED" param
    | CKA_KEY_TYPE, param ->
        p_key_type "CKA_KEY_TYPE" param
    | CKA_SUBJECT, param ->
        p_string "CKA_SUBJECT" param
    | CKA_ID, param ->
        p_string "CKA_ID" param
    | CKA_SENSITIVE, param ->
        p_bool "CKA_SENSITIVE" param
    | CKA_ENCRYPT, param ->
        p_bool "CKA_ENCRYPT" param
    | CKA_DECRYPT, param ->
        p_bool "CKA_DECRYPT" param
    | CKA_WRAP, param ->
        p_bool "CKA_WRAP" param
    | CKA_UNWRAP, param ->
        p_bool "CKA_UNWRAP" param
    | CKA_SIGN, param ->
        p_bool "CKA_SIGN" param
    | CKA_SIGN_RECOVER, param ->
        p_bool "CKA_SIGN_RECOVER" param
    | CKA_VERIFY, param ->
        p_bool "CKA_VERIFY" param
    | CKA_VERIFY_RECOVER, param ->
        p_bool "CKA_VERIFY_RECOVER" param
    | CKA_DERIVE, param ->
        p_bool "CKA_DERIVE" param
    | CKA_MODULUS, param ->
        p_bigint "CKA_MODULUS" param
    | CKA_MODULUS_BITS, param ->
        p_ulong "CKA_MODULUS_BITS" param
    | CKA_PUBLIC_EXPONENT, param ->
        p_bigint "CKA_PUBLIC_EXPONENT" param
    | CKA_PRIVATE_EXPONENT, param ->
        p_bigint "CKA_PRIVATE_EXPONENT" param
    | CKA_PRIME_1, param ->
        p_bigint "CKA_PRIME_1" param
    | CKA_PRIME_2, param ->
        p_bigint "CKA_PRIME_2" param
    | CKA_EXPONENT_1, param ->
        p_bigint "CKA_EXPONENT_1" param
    | CKA_EXPONENT_2, param ->
        p_bigint "CKA_EXPONENT_2" param
    | CKA_COEFFICIENT, param ->
        p_bigint "CKA_COEFFICIENT" param
    | CKA_PRIME, param ->
        p_bigint "CKA_PRIME" param
    | CKA_SUBPRIME, param ->
        p_bigint "CKA_SUBPRIME" param
    | CKA_VALUE_LEN, param ->
        p_ulong "CKA_VALUE_LEN" param
    | CKA_EXTRACTABLE, param ->
        p_bool "CKA_EXTRACTABLE" param
    | CKA_LOCAL, param ->
        p_bool "CKA_LOCAL" param
    | CKA_NEVER_EXTRACTABLE, param ->
        p_bool "CKA_NEVER_EXTRACTABLE" param
    | CKA_ALWAYS_SENSITIVE, param ->
        p_bool "CKA_ALWAYS_SENSITIVE" param
    | CKA_KEY_GEN_MECHANISM, param ->
        p_mechanism_type "CKA_KEY_GEN_MECHANISM" param
    | CKA_MODIFIABLE, param ->
        p_bool "CKA_MODIFIABLE" param
    | CKA_EC_PARAMS, param ->
        p_ec_params "CKA_EC_PARAMS" param
    | CKA_EC_POINT, param ->
        p_ec_point "CKA_EC_POINT" param
    | CKA_ALWAYS_AUTHENTICATE, param ->
        p_bool "CKA_ALWAYS_AUTHENTICATE" param
    | CKA_WRAP_WITH_TRUSTED, param ->
        p_bool "CKA_WRAP_WITH_TRUSTED" param
    | CKA_CHECK_VALUE, NOT_IMPLEMENTED param ->
        p_data "CKA_CHECK_VALUE" param
    | CKA_START_DATE, NOT_IMPLEMENTED param ->
        p_data "CKA_START_DATE" param
    | CKA_END_DATE, NOT_IMPLEMENTED param ->
        p_data "CKA_END_DATE" param
    | CKA_PRIME_BITS, param ->
        p_ulong "CKA_PRIME_BITS" param
    | CKA_SUBPRIME_BITS, param ->
        p_ulong "CKA_SUBPRIME_BITS" param
    | CKA_WRAP_TEMPLATE, NOT_IMPLEMENTED param ->
        p_data "CKA_WRAP_TEMPLATE" param
    | CKA_UNWRAP_TEMPLATE, NOT_IMPLEMENTED param ->
        p_data "CKA_UNWRAP_TEMPLATE" param
    | CKA_ALLOWED_MECHANISMS, NOT_IMPLEMENTED param ->
        p_data "CKA_ALLOWED_MECHANISMS" param
    | CKA_CS_UNKNOWN ul, NOT_IMPLEMENTED param ->
        p_data (Unsigned.ULong.to_string ul) param

let pack_of_yojson json : (pack, string) result =
  let parse name param : (pack, string) result =
    let parse_using f typ' =
      let open Ppx_deriving_yojson_runtime in
      f param >>= fun r ->
      Ok (Pack (typ', r))
    in
    let p_object_class = parse_using P11_object_class.of_yojson in
    let p_bool = parse_using (function
        | `Bool b -> Ok b
        | `String "CK_TRUE" -> Ok true
        | `String "CK_FALSE" -> Ok false
        | _ -> Error "Not a CK_BBOOL"
      ) in
    let p_string = parse_using [%of_yojson: string] in
    let p_data = parse_using P11_hex_data.of_yojson in
    let p_key_type = parse_using P11_key_type.of_yojson in
    let p_ulong = parse_using P11_ulong.of_yojson in
    let p_bigint = parse_using P11_bigint.of_yojson in
    let p_mechanism_type = parse_using P11_key_gen_mechanism.of_yojson in
    let p_ec_params = parse_using Key_parsers.Asn1.EC.Params.of_yojson in
    let p_ec_point = parse_using (fun js ->
        let open Ppx_deriving_yojson_runtime in
        P11_hex_data.of_yojson js >|= Cstruct.of_string
      )
    in
    let p_not_implemented typ' =
      let open Ppx_deriving_yojson_runtime in
      P11_hex_data.of_yojson param >>= fun p ->
      Ok (Pack (typ', P11_attribute_type.NOT_IMPLEMENTED p))
    in
    let open P11_attribute_type in
    match name with
      | "CKA_CLASS" ->
          p_object_class CKA_CLASS
      | "CKA_TOKEN" ->
          p_bool CKA_TOKEN
      | "CKA_PRIVATE" ->
          p_bool CKA_PRIVATE
      | "CKA_LABEL" ->
          p_string CKA_LABEL
      | "CKA_VALUE" ->
          p_data CKA_VALUE
      | "CKA_TRUSTED" ->
          p_bool CKA_TRUSTED
      | "CKA_KEY_TYPE" ->
          p_key_type CKA_KEY_TYPE
      | "CKA_SUBJECT" ->
          p_string CKA_SUBJECT
      | "CKA_ID" ->
          p_string CKA_ID
      | "CKA_SENSITIVE" ->
          p_bool CKA_SENSITIVE
      | "CKA_ENCRYPT" ->
          p_bool CKA_ENCRYPT
      | "CKA_DECRYPT" ->
          p_bool CKA_DECRYPT
      | "CKA_WRAP" ->
          p_bool CKA_WRAP
      | "CKA_UNWRAP" ->
          p_bool CKA_UNWRAP
      | "CKA_SIGN" ->
          p_bool CKA_SIGN
      | "CKA_SIGN_RECOVER" ->
          p_bool CKA_SIGN_RECOVER
      | "CKA_VERIFY" ->
          p_bool CKA_VERIFY
      | "CKA_VERIFY_RECOVER" ->
          p_bool CKA_VERIFY_RECOVER
      | "CKA_DERIVE" ->
          p_bool CKA_DERIVE
      | "CKA_MODULUS" ->
          p_bigint CKA_MODULUS
      | "CKA_MODULUS_BITS" ->
          p_ulong CKA_MODULUS_BITS
      | "CKA_PUBLIC_EXPONENT" ->
          p_bigint CKA_PUBLIC_EXPONENT
      | "CKA_PRIVATE_EXPONENT" ->
          p_bigint CKA_PRIVATE_EXPONENT
      | "CKA_PRIME_1" ->
          p_bigint CKA_PRIME_1
      | "CKA_PRIME_2" ->
          p_bigint CKA_PRIME_2
      | "CKA_EXPONENT_1" ->
          p_bigint CKA_EXPONENT_1
      | "CKA_EXPONENT_2" ->
          p_bigint CKA_EXPONENT_2
      | "CKA_COEFFICIENT" ->
          p_bigint CKA_COEFFICIENT
      | "CKA_PRIME" ->
          p_bigint CKA_PRIME
      | "CKA_SUBPRIME" ->
          p_bigint CKA_SUBPRIME
      | "CKA_VALUE_LEN" ->
          p_ulong CKA_VALUE_LEN
      | "CKA_EXTRACTABLE" ->
          p_bool CKA_EXTRACTABLE
      | "CKA_LOCAL" ->
          p_bool CKA_LOCAL
      | "CKA_NEVER_EXTRACTABLE" ->
          p_bool CKA_NEVER_EXTRACTABLE
      | "CKA_ALWAYS_SENSITIVE" ->
          p_bool CKA_ALWAYS_SENSITIVE
      | "CKA_KEY_GEN_MECHANISM" ->
          p_mechanism_type CKA_KEY_GEN_MECHANISM
      | "CKA_MODIFIABLE" ->
          p_bool CKA_MODIFIABLE
      | "CKA_EC_PARAMS" ->
          p_ec_params CKA_EC_PARAMS
      | "CKA_EC_POINT" ->
          p_ec_point CKA_EC_POINT
      | "CKA_ALWAYS_AUTHENTICATE" ->
          p_bool CKA_ALWAYS_AUTHENTICATE
      | "CKA_WRAP_WITH_TRUSTED" ->
          p_bool CKA_WRAP_WITH_TRUSTED
      | "CKA_CHECK_VALUE" ->
          p_not_implemented CKA_CHECK_VALUE
      | "CKA_START_DATE" ->
          p_not_implemented CKA_START_DATE
      | "CKA_END_DATE" ->
          p_not_implemented CKA_END_DATE
      | "CKA_PRIME_BITS" ->
          p_ulong CKA_PRIME_BITS
      | "CKA_SUBPRIME_BITS" ->
          p_ulong CKA_SUBPRIME_BITS
      | "CKA_WRAP_TEMPLATE" ->
          p_not_implemented CKA_WRAP_TEMPLATE
      | "CKA_UNWRAP_TEMPLATE" ->
          p_not_implemented CKA_UNWRAP_TEMPLATE
      | "CKA_ALLOWED_MECHANISMS" ->
          p_not_implemented CKA_ALLOWED_MECHANISMS
      | _ as ul ->
          try
            p_not_implemented
              (CKA_CS_UNKNOWN (Unsigned.ULong.of_string ul))
          with Failure _ -> Error "Invalid attribute"
  in
  match json with
    | `Assoc [ name, param ] ->
        parse name param
    | _ ->
        Error "Ill-formed attribute"

let pack_to_yojson (Pack x) = to_json x

let compare_types (a,_) (b,_) =
  P11_attribute_type.compare a b

let compare_types_pack (Pack (a, _)) (Pack (b, _)) =
  P11_attribute_type.compare a b

let compare_bool = [%ord: bool]
let compare_string = [%ord: string]
let compare_ulong = [%ord: P11_ulong.t]

let compare (type a) (type b) (a:a t) (b: b t) =
  let open P11_attribute_type in
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
          P11_object_class.compare a_param b_param
      | (CKA_KEY_TYPE, a_param), (CKA_KEY_TYPE, b_param) ->
          P11_key_type.compare a_param b_param
      | (CKA_MODULUS_BITS, a_param), (CKA_MODULUS_BITS, b_param) ->
          P11_ulong.compare a_param b_param
      | (CKA_VALUE_LEN, a_param), (CKA_VALUE_LEN, b_param) ->
          P11_ulong.compare a_param b_param
      | (CKA_KEY_GEN_MECHANISM, a_param), (CKA_KEY_GEN_MECHANISM, b_param) ->
          P11_key_gen_mechanism.compare a_param b_param
      | (CKA_EC_PARAMS, a_param), (CKA_EC_PARAMS, b_param) ->
          Key_parsers.Asn1.EC.Params.compare a_param b_param
      | (CKA_EC_POINT, a_param), (CKA_EC_POINT, b_param) ->
          Key_parsers.Asn1.EC.compare_point a_param b_param
      | (CKA_PUBLIC_EXPONENT, a_param), (CKA_PUBLIC_EXPONENT, b_param) -> P11_bigint.compare a_param b_param
      | (CKA_PRIVATE_EXPONENT, a_param), (CKA_PRIVATE_EXPONENT, b_param) -> P11_bigint.compare a_param b_param
      | (CKA_PRIME_1, a_param), (CKA_PRIME_1, b_param) -> P11_bigint.compare a_param b_param
      | (CKA_PRIME_2, a_param), (CKA_PRIME_2, b_param) -> P11_bigint.compare a_param b_param
      | (CKA_EXPONENT_1, a_param), (CKA_EXPONENT_1, b_param) -> P11_bigint.compare a_param b_param
      | (CKA_EXPONENT_2, a_param), (CKA_EXPONENT_2, b_param) -> P11_bigint.compare a_param b_param
      | (CKA_COEFFICIENT, a_param), (CKA_COEFFICIENT, b_param) -> P11_bigint.compare a_param b_param
      | (CKA_PRIME, a_param), (CKA_PRIME, b_param) -> P11_bigint.compare a_param b_param
      | (CKA_SUBPRIME, a_param), (CKA_SUBPRIME, b_param) -> P11_bigint.compare a_param b_param
      | (CKA_MODULUS, a_param), (CKA_MODULUS, b_param) -> P11_bigint.compare a_param b_param

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
      | (CKA_CHECK_VALUE, NOT_IMPLEMENTED a_param), (CKA_CHECK_VALUE, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_START_DATE, NOT_IMPLEMENTED a_param), (CKA_START_DATE, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_END_DATE, NOT_IMPLEMENTED a_param), (CKA_END_DATE, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_PRIME_BITS, a_param), (CKA_PRIME_BITS,  b_param) -> compare_ulong a_param b_param
      | (CKA_SUBPRIME_BITS, a_param), (CKA_SUBPRIME_BITS, b_param) -> compare_ulong a_param b_param
      | (CKA_WRAP_TEMPLATE, NOT_IMPLEMENTED a_param), (CKA_WRAP_TEMPLATE, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_UNWRAP_TEMPLATE, NOT_IMPLEMENTED a_param), (CKA_UNWRAP_TEMPLATE, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
      | (CKA_ALLOWED_MECHANISMS, NOT_IMPLEMENTED a_param), (CKA_ALLOWED_MECHANISMS, NOT_IMPLEMENTED b_param) -> compare_string a_param b_param
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
      | (CKA_EC_PARAMS, _), _ -> assert false
      | (CKA_EC_POINT, _), _ -> assert false
      | (CKA_CHECK_VALUE, _), _ -> assert false
      | (CKA_START_DATE, _), _ -> assert false
      | (CKA_END_DATE, _), _ -> assert false
      | (CKA_PRIME_BITS, _), _ -> assert false
      | (CKA_SUBPRIME_BITS, _), _ -> assert false
      | (CKA_WRAP_TEMPLATE, _), _ -> assert false
      | (CKA_UNWRAP_TEMPLATE, _), _ -> assert false
      | (CKA_ALLOWED_MECHANISMS, _), _ -> assert false
      | (CKA_CS_UNKNOWN _, _), _ -> assert false

let compare_pack (Pack a) (Pack b) = compare a b

let equal a b =
  compare a b = 0

let equal_pack (Pack a) (Pack b) = equal a b

let equal_types_pack a b = (compare_types_pack a b) = 0
let equal_values a v1 v2 = equal (a,v1) (a,v2)

let show_pack (Pack attr) =
  to_string attr

let pp_pack fmt pack =
  Format.pp_print_string fmt (show_pack pack)

type kind =
  | Secret (* Can be used by secret keys. *)
  | Public (* Can be used by public keys. *)
  | Private (* Can be used by private keys. *)
  | RSA (* Can ONLY be used by RSA keys. *)
  | EC (* Can ONLY be used by elliptic curves keys. *)

(* [kinds] returns a list of list.

   An attribute has kinds [ A; B; C ] if one of the lists returned by
   [kinds] has at least kinds [ A; B; C ]. *)
let kinds : pack -> _ = fun (Pack (a,_)) ->
  let open P11_attribute_type in
  let secret_public_private = [ [ Secret; Public; Private ] ] in
  let secret_public = [ [ Secret; Public ] ] in
  let secret_private = [ [ Secret; Private ] ] in
  let rsa_private = [ [ RSA; Private ] ] in
  match a with
    (* Common Object Attributes *)
    | CKA_CLASS -> secret_public_private
    (* Common Storage Object Attributes *)
    | CKA_TOKEN      -> secret_public_private
    | CKA_PRIVATE    -> secret_public_private
    | CKA_MODIFIABLE -> secret_public_private
    | CKA_LABEL      -> secret_public_private
    (* Common Key Attributes *)
    | CKA_KEY_TYPE          -> secret_public_private
    | CKA_ID                -> secret_public_private
    | CKA_DERIVE            -> secret_public_private
    | CKA_LOCAL             -> secret_public_private
    | CKA_KEY_GEN_MECHANISM -> secret_public_private
    (* Public and Secret Key Attributes *)
    | CKA_ENCRYPT        -> secret_public
    | CKA_VERIFY         -> secret_public
    | CKA_VERIFY_RECOVER -> secret_public
    | CKA_WRAP           -> secret_public
    | CKA_TRUSTED        -> secret_public
    (* Private and Secret Key Attributes *)
    | CKA_SENSITIVE           -> secret_private
    | CKA_DECRYPT             -> secret_private
    | CKA_SIGN                -> secret_private
    | CKA_SIGN_RECOVER        -> secret_private
    | CKA_UNWRAP              -> secret_private
    | CKA_EXTRACTABLE         -> secret_private
    | CKA_ALWAYS_SENSITIVE    -> secret_private
    | CKA_NEVER_EXTRACTABLE   -> secret_private
    | CKA_WRAP_WITH_TRUSTED   -> secret_private
    | CKA_ALWAYS_AUTHENTICATE -> secret_private
    (* Mechanism-Specific *)
    | CKA_VALUE            -> [ [ Secret ]; [ EC; Private ] ]
    | CKA_VALUE_LEN        -> [ [ Secret ] ]
    | CKA_MODULUS          -> [ [ RSA; Public; Private ] ]
    | CKA_PUBLIC_EXPONENT  -> [ [ RSA; Public; Private ] ]
    | CKA_MODULUS_BITS     -> [ [ RSA; Public ] ]
    | CKA_PRIVATE_EXPONENT -> rsa_private
    | CKA_PRIME_1          -> rsa_private
    | CKA_PRIME_2          -> rsa_private
    | CKA_EXPONENT_1       -> rsa_private
    | CKA_EXPONENT_2       -> rsa_private
    | CKA_COEFFICIENT      -> rsa_private
    | CKA_PRIME            -> []
    | CKA_SUBPRIME         -> []
    | CKA_EC_PARAMS        -> [ [ EC; Public; Private ] ]
    | CKA_EC_POINT         -> [ [ EC; Public ] ]
    | CKA_SUBJECT          -> [ [ Public; Private ] ]
    | CKA_CHECK_VALUE -> assert false
    | CKA_START_DATE -> assert false
    | CKA_END_DATE -> assert false
    | CKA_PRIME_BITS -> assert false
    | CKA_SUBPRIME_BITS -> assert false
    | CKA_WRAP_TEMPLATE -> assert false
    | CKA_UNWRAP_TEMPLATE -> assert false
    | CKA_ALLOWED_MECHANISMS -> assert false
    | CKA_CS_UNKNOWN _ -> []

(* Return whether [a] has all kinds [k]. *)
let is (k: kind list) (a: pack) =
  List.exists
    (fun kinds -> List.for_all (fun k -> List.mem k kinds) k)
    (kinds a)

let type_ (Pack (ty,_)) = P11_attribute_type.Pack ty

let equal_kind (x:kind) y =
  x = y
