type 'a t = 'a P11_attribute_type.t * 'a
type pack =
  Pkcs11.CK_ATTRIBUTE.pack = Pack : 'a t -> pack
[@@deriving eq,ord,show,yojson]

val to_string : 'a t -> string
val to_string_pair : 'a t -> string * string

val to_json : 'a t -> Yojson.Safe.json

val compare_types: 'a t -> 'b t -> int
val compare_types_pack: pack -> pack -> int
val compare: 'a t -> 'b t -> int
val equal: 'a t -> 'b t -> bool
val equal_types_pack: pack -> pack -> bool
val equal_values: 'a P11_attribute_type.t -> 'a -> 'a -> bool

type kind =
  | Secret (* Can be used by secret keys. *)
  | Public (* Can be used by public keys. *)
  | Private (* Can be used by private keys. *)
  | RSA (* Can ONLY be used by RSA keys. *)
  | EC (* Can ONLY be used by elliptic curves keys. *)

(** [kinds] returns a list of list.
   An attribute has kinds [ A; B; C ] if one of the lists returned by [kinds]
   has at least kinds [ A; B; C ]. *)
val kinds: pack -> kind list list

(** Return whether [a] has all kinds [k]. *)
val is : kind list -> pack -> bool

val equal_kind : kind -> kind -> bool

val type_ : pack -> P11_attribute_type.pack
