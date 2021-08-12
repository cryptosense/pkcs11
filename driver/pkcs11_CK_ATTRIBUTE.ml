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

let ( -: ) ty label = smart_field ck_attribute label ty

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
  setf a ulValueLen Unsigned.ULong.zero;
  a

(** [allocate t] updates the structure in place by allocating memory
    for the value. *)
let allocate (t : t) : unit =
  let count = Unsigned.ULong.to_int (getf t ulValueLen) in
  Reachable_ptr.setf t pValue (to_voidp (allocate_n char ~count));
  ()

let get_type t = getf t _type

let get_length t = Unsigned.ULong.to_int (getf t ulValueLen)

let pvalue_is_null_ptr t = is_null (Reachable_ptr.getf t pValue)

let unsafe_get_value typ t = from_voidp typ (Reachable_ptr.getf t pValue)

let ck_true : Pkcs11_CK_BBOOL.t ptr =
  Ctypes.allocate Pkcs11_CK_BBOOL.typ Pkcs11_CK_BBOOL._CK_TRUE

let ck_false : Pkcs11_CK_BBOOL.t ptr =
  Ctypes.allocate Pkcs11_CK_BBOOL.typ Pkcs11_CK_BBOOL._CK_FALSE

(* Constructors *)

let boolean attribute_type bool : t =
  let a = Ctypes.make ck_attribute in
  let bool =
    if bool then
      ck_true
    else
      ck_false
  in
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

let bigint attr_type u = string attr_type (P11_bigint.encode u)

(* Accessors *)

let unsafe_get_bool t =
  let p = unsafe_get_value uint8_t t in
  let b = !@p in
  Unsigned.UInt8.to_int b <> 0

let unsafe_get_byte t =
  let p = unsafe_get_value uint8_t t in
  let b = !@p in
  Unsigned.UInt8.to_int b

(** [unsafe_get_string] reads the length of the string in [t], so it
    is able to handle string with \000 inside. *)
let unsafe_get_string t =
  let length = get_length t in
  let p = unsafe_get_value char t in
  string_from_ptr p ~length

let unsafe_get_ulong t =
  let p = unsafe_get_value Ctypes.ulong t in
  !@p

let unsafe_get_object_class : t -> Pkcs11_CK_OBJECT_CLASS.t = unsafe_get_ulong

let unsafe_get_key_type : t -> Pkcs11_CK_KEY_TYPE.t = unsafe_get_ulong

let repr_view (type a) t : a P11_attribute.repr -> a =
  let open P11_attribute in
  let open P11_attribute_type in
  function
  | Repr_object_class -> Pkcs11_CK_OBJECT_CLASS.view (unsafe_get_object_class t)
  | Repr_bool -> unsafe_get_bool t
  | Repr_string -> unsafe_get_string t
  | Repr_data -> unsafe_get_string t
  | Repr_not_implemented -> NOT_IMPLEMENTED (unsafe_get_string t)
  | Repr_key_type -> Pkcs11_CK_KEY_TYPE.view (unsafe_get_key_type t)
  | Repr_bigint -> P11_bigint.decode (unsafe_get_string t)
  | Repr_ulong -> unsafe_get_ulong t
  | Repr_key_gen_mechanism -> Pkcs11_key_gen_mechanism.view (unsafe_get_ulong t)

let repr_make (type a) at (param : a) : a P11_attribute.repr -> _ =
  let open P11_attribute in
  function
  | Repr_object_class -> ulong at (Pkcs11_CK_OBJECT_CLASS.make param)
  | Repr_bool -> boolean at param
  | Repr_string -> string at param
  | Repr_data -> string at param
  | Repr_not_implemented ->
    let (P11_attribute_type.NOT_IMPLEMENTED s) = param in
    string at s
  | Repr_key_type -> ulong at (Pkcs11_CK_KEY_TYPE.make param)
  | Repr_bigint -> bigint at param
  | Repr_ulong -> ulong at param
  | Repr_key_gen_mechanism -> ulong at (Pkcs11_key_gen_mechanism.make param)

let view t =
  let open P11_attribute_type in
  let ul = getf t _type in
  let (Pack attribute_type) = Pkcs11_CK_ATTRIBUTE_TYPE.view ul in
  let repr = P11_attribute.repr attribute_type in
  let param = repr_view t repr in
  pack (attribute_type, param)

let make (type s) ((at, param) : s u) =
  repr_make (Pkcs11_CK_ATTRIBUTE_TYPE.make at) param (P11_attribute.repr at)

let make_pack (P11_attribute.Pack x) = make x

let compare_types = P11_attribute.compare_types

let compare_types_pack = P11_attribute.compare_types_pack

let compare = P11_attribute.compare

let compare_pack = P11_attribute.compare_pack

let equal = P11_attribute.equal

let equal_pack = P11_attribute.equal_pack
