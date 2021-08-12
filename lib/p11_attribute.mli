type 'a t = 'a P11_attribute_type.t * 'a

type pack = Pack : 'a t -> pack [@@deriving eq, ord, show, yojson]

val to_string : 'a t -> string

val to_string_pair : 'a t -> string * string

val to_json : 'a t -> Yojson.Safe.t

val compare_types : 'a t -> 'b t -> int

val compare_types_pack : pack -> pack -> int

val compare : 'a t -> 'b t -> int

val equal : 'a t -> 'b t -> bool

val equal_types_pack : pack -> pack -> bool

val equal_values : 'a P11_attribute_type.t -> 'a -> 'a -> bool

val type_ : pack -> P11_attribute_type.pack

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

val repr : 'a P11_attribute_type.t -> 'a repr
(** Return how this attribute type is represented.
    This is an implementation detail, do not rely on this outside of [pkcs11]. *)
