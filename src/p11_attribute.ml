type 'a t = 'a P11_attribute_type.t * 'a

type pack = Pack : 'a t -> pack

type _ repr =
   | Repr_object_class : P11_object_class.t repr
   | Repr_bool : bool repr
   | Repr_string : string repr
   | Repr_key_type : P11_key_type.t repr
   | Repr_not_implemented : P11_attribute_type.not_implemented repr
   | Repr_bigint : P11_bigint.t repr
   | Repr_ulong : Unsigned.ULong.t repr
   | Repr_key_gen_mechanism : P11_key_gen_mechanism.t repr
   | Repr_data : string repr

let repr (type a) : a P11_attribute_type.t -> a repr =
  let open P11_attribute_type in
  function
  | CKA_CLASS -> Repr_object_class
  | CKA_TOKEN -> Repr_bool
  | CKA_PRIVATE -> Repr_bool
  | CKA_LABEL -> Repr_string
  | CKA_VALUE -> Repr_data
  | CKA_TRUSTED -> Repr_bool
  | CKA_CHECK_VALUE -> Repr_not_implemented
  | CKA_KEY_TYPE -> Repr_key_type
  | CKA_SUBJECT -> Repr_string
  | CKA_ID -> Repr_data
  | CKA_SENSITIVE -> Repr_bool
  | CKA_ENCRYPT -> Repr_bool
  | CKA_DECRYPT -> Repr_bool
  | CKA_WRAP -> Repr_bool
  | CKA_UNWRAP -> Repr_bool
  | CKA_SIGN -> Repr_bool
  | CKA_SIGN_RECOVER -> Repr_bool
  | CKA_VERIFY -> Repr_bool
  | CKA_VERIFY_RECOVER -> Repr_bool
  | CKA_DERIVE -> Repr_bool
  | CKA_START_DATE -> Repr_not_implemented
  | CKA_END_DATE -> Repr_not_implemented
  | CKA_MODULUS -> Repr_bigint
  | CKA_MODULUS_BITS -> Repr_ulong
  | CKA_PUBLIC_EXPONENT -> Repr_bigint
  | CKA_PRIVATE_EXPONENT -> Repr_bigint
  | CKA_PRIME_1 -> Repr_bigint
  | CKA_PRIME_2 -> Repr_bigint
  | CKA_EXPONENT_1 -> Repr_bigint
  | CKA_EXPONENT_2 -> Repr_bigint
  | CKA_COEFFICIENT -> Repr_bigint
  | CKA_PRIME -> Repr_bigint
  | CKA_SUBPRIME -> Repr_bigint
  | CKA_BASE -> Repr_bigint
  | CKA_PRIME_BITS -> Repr_ulong
  | CKA_SUBPRIME_BITS -> Repr_ulong
  | CKA_VALUE_LEN -> Repr_ulong
  | CKA_EXTRACTABLE -> Repr_bool
  | CKA_LOCAL -> Repr_bool
  | CKA_NEVER_EXTRACTABLE -> Repr_bool
  | CKA_ALWAYS_SENSITIVE -> Repr_bool
  | CKA_KEY_GEN_MECHANISM -> Repr_key_gen_mechanism
  | CKA_MODIFIABLE -> Repr_bool
  | CKA_EC_PARAMS -> Repr_data
  | CKA_EC_POINT -> Repr_data
  | CKA_ALWAYS_AUTHENTICATE -> Repr_bool
  | CKA_WRAP_WITH_TRUSTED -> Repr_bool
  | CKA_WRAP_TEMPLATE -> Repr_not_implemented
  | CKA_UNWRAP_TEMPLATE -> Repr_not_implemented
  | CKA_ALLOWED_MECHANISMS -> Repr_not_implemented
  | CKA_CS_UNKNOWN _ -> Repr_not_implemented

let bool_to_string = function
  | true -> "CK_TRUE"
  | false -> "CK_FALSE"

let to_string_value (type a) : a repr -> a -> string =
  let open P11_attribute_type in
  let string x = Printf.sprintf "%S" x in
  let not_implemented (NOT_IMPLEMENTED x) = string x in
  function
  | Repr_object_class -> P11_object_class.to_string
  | Repr_bool -> bool_to_string
  | Repr_string -> string
  | Repr_key_type -> P11_key_type.to_string
  | Repr_not_implemented -> not_implemented
  | Repr_bigint -> P11_bigint.to_string
  | Repr_ulong -> Unsigned.ULong.to_string
  | Repr_key_gen_mechanism -> P11_key_gen_mechanism.to_string
  | Repr_data -> string

let to_string_pair (type s) (x : s t) =
  let open P11_attribute_type in
  let cka = to_string (fst x) in
  let repr = repr (fst x) in
  (cka, to_string_value repr (snd x))

let to_string x =
  let a, b = to_string_pair x in
  Printf.sprintf "%s %s" a b

(* Note: it is important for [Template.to_json] and [Template.of_json]
   that all attributes are represented using [`Assoc]. *)
let to_json : type a . a t -> Yojson.Safe.json = fun attribute ->
  let key_json = P11_attribute_type.to_string (fst attribute) in
  let data = P11_hex_data.to_yojson in
  let value_json =
    match repr (fst attribute), snd attribute with
    | Repr_object_class, param -> P11_object_class.to_yojson param
    | Repr_bool, param -> `String (bool_to_string param)
    | Repr_string, param -> (fun s -> `String s) param
    | Repr_key_type, param -> P11_key_type.to_yojson param
    | Repr_not_implemented, NOT_IMPLEMENTED param -> data param
    | Repr_bigint, param -> P11_bigint.to_yojson param
    | Repr_ulong, param -> P11_ulong.to_yojson param
    | Repr_key_gen_mechanism, param -> P11_key_gen_mechanism.to_yojson param
    | Repr_data, param -> data param
  in
  `Assoc [(key_json, value_json)]

let of_yojson_repr (type a) (repr : a repr) : Yojson.Safe.json -> (a, string) result =
  let (>>=) = Ppx_deriving_yojson_runtime.(>>=) in
  let bool_of_yojson = function
    | `Bool b -> Ok b
    | `String "CK_TRUE" -> Ok true
    | `String "CK_FALSE" -> Ok false
    | _ -> Error "Not a CK_BBOOL"
  in
  let parse_not_implemented x =
    P11_hex_data.of_yojson x >>= fun s ->
    Ok (P11_attribute_type.NOT_IMPLEMENTED s)
  in
  match repr with
  | Repr_object_class -> P11_object_class.of_yojson
  | Repr_bool -> bool_of_yojson
  | Repr_string -> [%of_yojson: string]
  | Repr_key_type -> P11_key_type.of_yojson
  | Repr_not_implemented -> parse_not_implemented
  | Repr_bigint -> P11_bigint.of_yojson
  | Repr_ulong -> P11_ulong.of_yojson
  | Repr_key_gen_mechanism -> P11_key_gen_mechanism.of_yojson
  | Repr_data -> P11_hex_data.of_yojson

let pack_of_yojson json : (pack, string) result =
  let (>>=) = Ppx_deriving_yojson_runtime.(>>=) in
  let of_string s =
    try
      Ok (P11_attribute_type.of_string s)
    with
    | Invalid_argument _ -> Error "Invalid attribute"
  in
  match json with
  | `Assoc [ (name, param) ] ->
    of_string name >>= fun (P11_attribute_type.Pack attr) ->
    of_yojson_repr (repr attr) param >>= fun r ->
    Ok (Pack (attr, r))
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
      | (CKA_EC_PARAMS, a_param), (CKA_EC_PARAMS, b_param) -> compare_string a_param b_param
      | (CKA_EC_POINT, a_param), (CKA_EC_POINT, b_param) -> compare_string a_param b_param
      | (CKA_PUBLIC_EXPONENT, a_param), (CKA_PUBLIC_EXPONENT, b_param) -> P11_bigint.compare a_param b_param
      | (CKA_PRIVATE_EXPONENT, a_param), (CKA_PRIVATE_EXPONENT, b_param) -> P11_bigint.compare a_param b_param
      | (CKA_PRIME_1, a_param), (CKA_PRIME_1, b_param) -> P11_bigint.compare a_param b_param
      | (CKA_PRIME_2, a_param), (CKA_PRIME_2, b_param) -> P11_bigint.compare a_param b_param
      | (CKA_EXPONENT_1, a_param), (CKA_EXPONENT_1, b_param) -> P11_bigint.compare a_param b_param
      | (CKA_EXPONENT_2, a_param), (CKA_EXPONENT_2, b_param) -> P11_bigint.compare a_param b_param
      | (CKA_COEFFICIENT, a_param), (CKA_COEFFICIENT, b_param) -> P11_bigint.compare a_param b_param
      | (CKA_PRIME, a_param), (CKA_PRIME, b_param) -> P11_bigint.compare a_param b_param
      | (CKA_SUBPRIME, a_param), (CKA_SUBPRIME, b_param) -> P11_bigint.compare a_param b_param
      | (CKA_BASE, a_param), (CKA_BASE, b_param) -> P11_bigint.compare a_param b_param
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
      | (CKA_BASE, _), _ -> assert false
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
    | CKA_BASE             -> []
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
