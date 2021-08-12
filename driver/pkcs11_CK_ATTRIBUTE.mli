(** Attributes (with values). *)
type _t

type t = _t Ctypes.structure

type 'a u = 'a P11_attribute_type.t * 'a

val boolean : Pkcs11_CK_ATTRIBUTE_TYPE.t -> bool -> t

val byte : Pkcs11_CK_ATTRIBUTE_TYPE.t -> int -> t

val ulong : Pkcs11_CK_ATTRIBUTE_TYPE.t -> P11_ulong.t -> t

val string : Pkcs11_CK_ATTRIBUTE_TYPE.t -> string -> t

val bigint : Pkcs11_CK_ATTRIBUTE_TYPE.t -> P11_bigint.t -> t

val create : Pkcs11_CK_ATTRIBUTE_TYPE.t -> t

val allocate : t -> unit

val get_type : t -> Pkcs11_CK_ATTRIBUTE_TYPE.t

val get_length : t -> int

val pvalue_is_null_ptr : t -> bool

val unsafe_get_bool : t -> bool

val unsafe_get_string : t -> string

val unsafe_get_byte : t -> int

val unsafe_get_ulong : t -> P11_ulong.t

val unsafe_get_object_class : t -> Pkcs11_CK_OBJECT_CLASS.t

val unsafe_get_key_type : t -> Pkcs11_CK_KEY_TYPE.t

val view : t -> P11_attribute.pack

val make : 'a u -> t

val make_pack : P11_attribute.pack -> t

val compare : 'a u -> 'b u -> int

val equal : 'a u -> 'b u -> bool

val equal_pack : P11_attribute.pack -> P11_attribute.pack -> bool

val compare_types : 'a u -> 'b u -> int

val compare_types_pack : P11_attribute.pack -> P11_attribute.pack -> int

val ck_attribute : t Ctypes.typ

val ulValueLen : (Unsigned.ulong, t) Ctypes.field

val pValue : (unit Ctypes_helpers.Reachable_ptr.t, t) Ctypes.field
