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
  let (a, b) = to_string_pair x in
  Printf.sprintf "%s %s" a b

(* Note: it is important for [Template.to_json] and [Template.of_json]
   that all attributes are represented using [`Assoc]. *)
let to_json : type a. a t -> Yojson.Safe.t =
 fun attribute ->
  let key_json = P11_attribute_type.to_string (fst attribute) in
  let data = P11_hex_data.to_yojson in
  let value_json =
    match (repr (fst attribute), snd attribute) with
    | (Repr_object_class, param) -> P11_object_class.to_yojson param
    | (Repr_bool, param) -> `String (bool_to_string param)
    | (Repr_string, param) -> (fun s -> `String s) param
    | (Repr_key_type, param) -> P11_key_type.to_yojson param
    | (Repr_not_implemented, NOT_IMPLEMENTED param) -> data param
    | (Repr_bigint, param) -> P11_bigint.to_yojson param
    | (Repr_ulong, param) -> P11_ulong.to_yojson param
    | (Repr_key_gen_mechanism, param) -> P11_key_gen_mechanism.to_yojson param
    | (Repr_data, param) -> data param
  in
  `Assoc [(key_json, value_json)]

let of_yojson_repr (type a) (repr : a repr) :
    Yojson.Safe.t -> (a, string) result =
  let ( >>= ) = Ppx_deriving_yojson_runtime.( >>= ) in
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
  let ( >>= ) = Ppx_deriving_yojson_runtime.( >>= ) in
  let of_string s =
    try Ok (P11_attribute_type.of_string s) with
    | Invalid_argument _ -> Error "Invalid attribute"
  in
  match json with
  | `Assoc [(name, param)] ->
    of_string name >>= fun (P11_attribute_type.Pack attr) ->
    of_yojson_repr (repr attr) param >>= fun r -> Ok (Pack (attr, r))
  | _ -> Error "Ill-formed attribute"

let pack_to_yojson (Pack x) = to_json x

let compare_types (a, _) (b, _) = P11_attribute_type.compare a b

let compare_types_pack (Pack (a, _)) (Pack (b, _)) =
  P11_attribute_type.compare a b

let compare_string = [%ord: string]

let compare_not_implemented
    (P11_attribute_type.NOT_IMPLEMENTED a)
    (P11_attribute_type.NOT_IMPLEMENTED b) =
  compare_string a b

let compare_using_repr (type a) (repr : a repr) : a -> a -> int =
  match repr with
  | Repr_object_class -> P11_object_class.compare
  | Repr_bool -> [%ord: bool]
  | Repr_string -> compare_string
  | Repr_key_type -> P11_key_type.compare
  | Repr_not_implemented -> compare_not_implemented
  | Repr_bigint -> P11_bigint.compare
  | Repr_ulong -> P11_ulong.compare
  | Repr_key_gen_mechanism -> P11_key_gen_mechanism.compare
  | Repr_data -> compare_string

let compare (type a b) ((ta, va) : a t) ((tb, vb) : b t) =
  let open P11_attribute_type in
  match compare' ta tb with
  | Not_equal r -> r
  | Equal -> compare_using_repr (repr ta) va vb

let compare_pack (Pack a) (Pack b) = compare a b

let equal a b = compare a b = 0

let equal_pack (Pack a) (Pack b) = equal a b

let equal_types_pack a b = compare_types_pack a b = 0

let equal_values a v1 v2 = equal (a, v1) (a, v2)

let show_pack (Pack attr) = to_string attr

let pp_pack fmt pack = Format.pp_print_string fmt (show_pack pack)

let type_ (Pack (ty, _)) = P11_attribute_type.Pack ty
