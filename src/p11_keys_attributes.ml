type kind =
  [ `AES
  | `DES
  | `DES3
  | `EC_private
  | `EC_public
  | `RSA_private
  | `RSA_public
  | `Secret
  ]

(** Representation used internally, it prevents repetitions. *)
module Internal_kind =
struct

  type t =
    [
      | `Secret
      | `RSA_public
      | `RSA_private
      | `EC_public
      | `EC_private
      | `Generic_secret
      | `Fixed_length_secret
    ] [@@deriving ord]

  let of_kind : kind -> t = function
    | `Secret -> `Secret
    | `RSA_public -> `RSA_public
    | `RSA_private -> `RSA_private
    | `EC_public -> `EC_public
    | `EC_private -> `EC_private
    | `AES ->  `Generic_secret
    | `DES -> `Fixed_length_secret
    | `DES3 -> `Fixed_length_secret

end
open P11.Attribute_type

module Kind_map = Map.Make(Internal_kind)

let p x = Pack x

let object_ =
  [
    p CKA_CLASS;
  ]

let storage =
  [
    p CKA_TOKEN;
    p CKA_PRIVATE;
    p CKA_MODIFIABLE;
    p CKA_LABEL;
  ]@object_

let key =
  [
    p CKA_KEY_TYPE;
    p CKA_ID;
    p CKA_START_DATE;
    p CKA_END_DATE;
    p CKA_DERIVE;
    p CKA_LOCAL;
    p CKA_KEY_GEN_MECHANISM;
    p CKA_ALLOWED_MECHANISMS;
  ]@storage

let public =
  [
    p CKA_SUBJECT;
    p CKA_ENCRYPT;
    p CKA_VERIFY;
    p CKA_VERIFY_RECOVER;
    p CKA_WRAP;
    p CKA_TRUSTED;
    p CKA_WRAP_TEMPLATE;
  ]@key

let private_ =
  [
    p CKA_SUBJECT;
    p CKA_SENSITIVE;
    p CKA_DECRYPT;
    p CKA_SIGN;
    p CKA_SIGN_RECOVER;
    p CKA_UNWRAP;
    p CKA_EXTRACTABLE;
    p CKA_ALWAYS_SENSITIVE;
    p CKA_NEVER_EXTRACTABLE;
    p CKA_WRAP_WITH_TRUSTED;
    p CKA_UNWRAP_TEMPLATE;
    p CKA_ALWAYS_AUTHENTICATE;
  ]@key

let secret =
  [
    p CKA_SENSITIVE;
    p CKA_ENCRYPT;
    p CKA_DECRYPT;
    p CKA_SIGN;
    p CKA_VERIFY;
    p CKA_WRAP;
    p CKA_UNWRAP;
    p CKA_EXTRACTABLE;
    p CKA_ALWAYS_SENSITIVE;
    p CKA_NEVER_EXTRACTABLE;
    p CKA_CHECK_VALUE;
    p CKA_WRAP_WITH_TRUSTED;
    p CKA_TRUSTED;
    p CKA_WRAP_TEMPLATE;
    p CKA_UNWRAP_TEMPLATE;
  ]@key

let rsa_public =
  [
    p CKA_MODULUS;
    p CKA_MODULUS_BITS;
    p CKA_PUBLIC_EXPONENT;
  ]@public

let rsa_private =
  [
    p CKA_MODULUS;
    p CKA_PUBLIC_EXPONENT;
    p CKA_PRIVATE_EXPONENT;
    p CKA_PRIME_1;
    p CKA_PRIME_2;
    p CKA_EXPONENT_1;
    p CKA_EXPONENT_2;
    p CKA_COEFFICIENT;
  ]@private_

let ec_public =
  [
    p CKA_EC_PARAMS;
    p CKA_EC_POINT;
  ]@public

let ec_private =
  [
    p CKA_EC_PARAMS;
    p CKA_VALUE;
  ]@private_

let generic_secret =
  [
    p CKA_VALUE;
    p CKA_VALUE_LEN;
  ]@secret

let fixed_length_secret =
  [
    p CKA_VALUE;
  ]@secret

let kind_attributes : P11.Attribute_types.t Kind_map.t=
  let add k v m = Kind_map.add k v m in
  Kind_map.empty
  |> add `Secret secret
  |> add `RSA_public rsa_public
  |> add `RSA_private rsa_private
  |> add `EC_public ec_public
  |> add `EC_private ec_private
  |> add `Generic_secret generic_secret
  |> add `Fixed_length_secret fixed_length_secret

let possible kind =
  try
    (Kind_map.find (Internal_kind.of_kind kind) kind_attributes)
  with Not_found -> []
