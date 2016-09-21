type kind =
  [
    | `Key
    | `Public
    | `Private
    | `Secret
    (* | `OTP (* V2.20 amendment 1 *) *)
    | `RSA_public
    | `RSA_private
    | `DSA_public
    | `DSA_private
    | `EC_public
    | `EC_private
    | `DH_public
    | `DH_private
    | `DH_X9_42_public
    | `DH_X9_42_private
    | `KEA_public
    | `KEA_private
    | `Generic_secret
    | `RC2
    | `RC4
    | `RC5
    | `AES
    | `DES
    | `CAST
    | `CAST3
    | `CAST128
    | `IDEA
    | `CDMF
    | `DES2
    | `DES3
    | `SKIPJACK
    | `BATON
    | `JUNIPER
    | `BLOWFISH
    | `TWOFISH
          (*
    | `CAMELLIA (* V2.20 amendment 3 *)
    | `ARIA (* V2.20 amendment 3 *)
    | `ACTI (* V2.20 amendment 1 *)
    | `SEED (* V2.30 *)
    | `SECURID (* V2.20 amendment 1 *)
    | `HOTP (* V2.20 amendment 1 *)
    | `GOST_28147_89 (* V2.30 *)
    | `GOST_R_34_10_2001_public (* V2.30 *)
    | `GOST_R_34_10_2001_private (* V2.30 *)
    *)
    | `VENDOR_DEFINED
  ] [@@deriving ord]

(** Representation used internally, it prevents repetitions. *)
module Internal_kind =
struct

  type t =
    [
      | `Key
      | `Public
      | `Private
      | `Secret
      (* | `OTP *)
      | `RSA_public
      | `RSA_private
      | `DSA_public
      | `DSA_private
      | `EC_public
      | `EC_private
      | `DH_public
      | `DH_private
      | `DH_X9_42_public
      | `DH_X9_42_private
      | `KEA_public
      | `KEA_private
      (*
      | `SECURID
      | `GOST_28147_89
      | `GOST_R_34_10_2001_public
      | `GOST_R_34_10_2001_private
      *)
      | `Generic_secret
      | `Fixed_length_secret
    ] [@@deriving ord]

  let to_kinds : t -> kind list = function
    | `Key -> [`Key]
    | `Public -> [`Key; `Public]
    | `Private -> [`Key; `Private]
    | `Secret -> [`Key; `Secret]
    (*    | `OTP -> [`Key; `Secret; `OTP; `HOTP; `ACTI]*)
    | `RSA_public -> [`Key; `Public; `RSA_public]
    | `RSA_private -> [`Key; `Private; `RSA_private]
    | `DSA_public -> [`Key; `Public; `DSA_public]
    | `DSA_private -> [`Key; `Private; `DSA_private]
    | `EC_public -> [`Key; `Public; `EC_public]
    | `EC_private -> [`Key; `Private; `EC_private]
    | `DH_public -> [`Key; `Public; `DH_public]
    | `DH_private -> [`Key; `Private; `DH_private]
    | `DH_X9_42_public -> [`Key; `Public; `DH_X9_42_public]
    | `DH_X9_42_private -> [`Key; `Private; `DH_X9_42_private]
    | `KEA_public -> [`Key; `Public; `KEA_public]
    | `KEA_private -> [`Key; `Private; `KEA_private]
    (*
    | `SECURID -> [`Key; `Secret; `OTP; `SECURID]
    | `GOST_28147_89 -> [`Key; `Secret; `GOST_28147_89]
    | `GOST_R_34_10_2001_public -> [`Key; `Public; `GOST_R_34_10_2001_public]
    | `GOST_R_34_10_2001_private -> [`Key; `Private; `GOST_R_34_10_2001_private]
    *)
    | `Generic_secret ->
        [
          `Key;
          `Secret;
          `Generic_secret;
          `RC2;
          `RC4;
          `RC5;
          `AES;
          `CAST;
          `CAST3;
          `CAST128;
          `BLOWFISH;
          `TWOFISH;
          (*
          `CAMELLIA;
          `ARIA;
           *)
        ]
    | `Fixed_length_secret ->
        [
          `Key;
          `Secret;
          `DES;
          `DES2;
          `DES3;
          `IDEA;
          `CDMF;
          `SKIPJACK;
          `BATON;
          `JUNIPER;
          (*`SEED;*)
        ]

  let of_kind : kind -> t = function
    | `Key -> `Key
    | `Public -> `Public
    | `Private -> `Private
    | `Secret -> `Secret
    (* | `OTP -> `OTP*)
    | `RSA_public -> `RSA_public
    | `RSA_private -> `RSA_private
    | `DSA_public -> `DSA_public
    | `DSA_private -> `DSA_private
    | `EC_public -> `EC_public
    | `EC_private -> `EC_private
    | `DH_public -> `DH_public
    | `DH_private -> `DH_private
    | `DH_X9_42_public -> `DH_X9_42_public
    | `DH_X9_42_private -> `DH_X9_42_private
    | `KEA_public -> `KEA_public
    | `KEA_private -> `KEA_private
    (*
    | `SECURID -> `SECURID
    (* There is no specific attribute for HOTP and ACTI, we can conside it like an OTP key.*)
    | `HOTP -> `OTP
    | `ACTI -> `OTP
    | `GOST_28147_89 -> `GOST_28147_89
    | `GOST_R_34_10_2001_public -> `GOST_R_34_10_2001_public
    | `GOST_R_34_10_2001_private -> `GOST_R_34_10_2001_private
    *)
    | `RC2
    | `RC4
    | `RC5
    | `AES
    | `CAST
    | `CAST3
    | `CAST128
    | `BLOWFISH
    | `TWOFISH
    (*
    | `CAMELLIA
    | `ARIA
    *)
    | `Generic_secret ->  `Generic_secret
    | `DES
    | `IDEA
    | `CDMF
    | `DES2
    | `DES3
    | `SKIPJACK
    | `BATON
    | `JUNIPER
    (*| `SEED*)
    | `VENDOR_DEFINED -> `Fixed_length_secret

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

(*
let otp =
  [
    p CKA_OTP_FORMAT;
    p CKA_OTP_LENGTH;
    p CKA_OTP_USER_FRIENDLY_MODE;
    p CKA_OTP_CHALLENGE_REQUIREMENT;
    p CKA_OTP_TIME_REQUIREMENT;
    p CKA_OTP_COUNTER_REQUIREMENT;
    p CKA_OTP_PIN_REQUIREMENT;
    p CKA_OTP_COUNTER;
    p CKA_OTP_TIME;
    p CKA_OTP_USER_IDENTIFIER;
    p CKA_OTP_SERVICE_IDENTIFIER;
    p CKA_OTP_SERVICE_LOGO;
    p CKA_OTP_SERVICE_LOGO_TYPE;
    p CKA_VALUE;
    p CKA_VALUE_LEN;
  ]@secret
*)

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

let dsa_public =
  [
    p CKA_PRIME;
    p CKA_SUBPRIME;
    p CKA_BASE;
    p CKA_VALUE;
  ]@public

let dsa_private =
  [
    p CKA_PRIME;
    p CKA_SUBPRIME;
    p CKA_BASE;
    p CKA_VALUE;
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

let dh_public =
  [
    p CKA_PRIME;
    p CKA_BASE;
    p CKA_VALUE;
  ]@public

let dh_x9_42_public = (p CKA_SUBPRIME)::dh_public

let dh_private =
  [
    p CKA_PRIME;
    p CKA_BASE;
    p CKA_VALUE;
    p CKA_VALUE_BITS;
  ]@private_

let dh_x9_42_private =
  [
    p CKA_PRIME;
    p CKA_BASE;
    p CKA_VALUE;
    p CKA_SUBPRIME;
  ]@private_

let kea_public = dh_x9_42_public

let kea_private = dh_x9_42_private

let generic_secret =
  [
    p CKA_VALUE;
    p CKA_VALUE_LEN;
  ]@secret

let fixed_length_secret =
  [
    p CKA_VALUE;
  ]@secret

(*
let securid =
  [
    p CKA_OTP_TIME_INTERVAL;
  ]@otp

let gost_28147_89 =
  [
    p CKA_VALUE;
    p CKA_GOST28147_PARAMS;
  ]@secret

let gost_r_34_10_2001_public =
  [
    p CKA_VALUE;
    p CKA_GOSTR3410_PARAMS;
    p CKA_GOSTR3411_PARAMS;
    p CKA_GOST28147_PARAMS;
  ]@public

let gost_r_34_10_2001_private =
  [
    p CKA_VALUE;
    p CKA_GOSTR3410_PARAMS;
    p CKA_GOSTR3411_PARAMS;
    p CKA_GOST28147_PARAMS;
  ]@private_
*)

let kind_attributes : P11.Attribute_types.t Kind_map.t=
  let open Kind_map in
  empty
  |> add `Key key
  |> add `Public public
  |> add `Private private_
  |> add `Secret secret
  (*  |> add `OTP otp*)
  |> add `RSA_public rsa_public
  |> add `RSA_private rsa_private
  |> add `DSA_public dsa_public
  |> add `DSA_private dsa_private
  |> add `EC_public ec_public
  |> add `EC_private ec_private
  |> add `DH_public dh_public
  |> add `DH_private dh_private
  |> add `DH_X9_42_public dh_x9_42_public
  |> add `DH_X9_42_private dh_x9_42_private
  |> add `KEA_public kea_public
  |> add `KEA_private kea_private
  (*
      |> add `SECURID securid
      |> add `GOST_28147_89 gost_28147_89
      |> add `GOST_R_34_10_2001_public gost_r_34_10_2001_public
      |> add `GOST_R_34_10_2001_private gost_r_34_10_2001_private
  *)
  |> add `Generic_secret generic_secret
  |> add `Fixed_length_secret fixed_length_secret

let possibles kind =
  try
    (Kind_map.find (Internal_kind.of_kind kind) kind_attributes)
  with Not_found -> []

let kinds attribute =
  Kind_map.filter
    (fun _ x -> List.exists (P11.Attribute_type.equal_pack attribute) x)
    kind_attributes
  |> Kind_map.bindings
  |> List.map fst
  |> List.fold_left (fun acc x -> (Internal_kind.to_kinds x)@acc) []
  |> List.sort_uniq compare_kind

let is kinds attribute =
  List.for_all
    (fun kind ->
       try
         List.exists (P11.Attribute_type.equal_pack attribute)
         @@ Kind_map.find (Internal_kind.of_kind kind) kind_attributes
       with Not_found -> false
    )
    kinds
