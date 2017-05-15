type t = P11_attribute.pack list
  [@@deriving yojson]

val to_string : t -> string
val pp : Format.formatter -> t -> unit

(** Return the value of the first occurrence of an attribute. *)
val get : t -> 'a P11_attribute_type.t -> 'a option
val get_pack : t -> P11_attribute_type.pack -> P11_attribute.pack option

val mem : P11_attribute.pack -> t -> bool

val of_raw : Pkcs11.Template.t -> t

val normalize: t -> t

(** Compares two normalized templates.  *)
val compare : t -> t -> int

val attribute_types: t -> P11_attribute_type.pack list

(** [set_attribute attribute template] replaces the value of
    [attribute] in [template] if it already exists and adds
    [attribute] otherwise. *)
val set_attribute : P11_attribute.pack -> t -> t

(** [remove_attribute attribute template] removes the value
    [attribute] from [template] if present. If the attribute_type of
    [attribute] is present with a different value, does nothing. *)
val remove_attribute: P11_attribute.pack -> t -> t

(** [remove_attribute attribute_type template] removes the attribute
    type [attribute_type] from [template] if present with any
    value. *)
val remove_attribute_type: P11_attribute_type.pack -> t -> t

(** Iterate one of the above operation. Same as List.fold_right*)
val fold: ('a -> t -> t) -> 'a list -> t -> t

(** [union template1 template2] concatenates the templates. If an
    attribute is present in both [template1] and [template2], the
    value in [template1] is kept. *)
val union : t -> t -> t

(** [only_attribute_types attr_types template] keeps only the
    attributes in [template] that are present in [attr_types]. *)
val only_attribute_types : P11_attribute_type.pack list -> t -> t

(** [except_attribute_types attr_types template] removes all the
    attributes in [template] that are present in [attr_types]. *)
val except_attribute_types : P11_attribute_type.pack list -> t -> t

(** [find_attribute_types l template] look up for the value of each
    attribute type in the list l in [template]. Return [None] if one
    or several attribute types cannot be found in [template]. *)
val find_attribute_types : P11_attribute_type.pack list -> t -> t option

(** [correspond source tested] check if [tested] match
    [source].
    It means that it will return true if All the elements
    in [source] are present in [tested].
*)
val correspond : source:t -> tested:t -> bool

(** [diff source tested] search for all the elements of [source]
    that are not equal to an element of [tested].

    It returns a tuple with the list of elements from source
    which are expected but not found in tested and a list of elements
    which are found but with a different value.
*)
val diff : source:t -> tested:t -> P11_attribute.pack list * P11_attribute.pack list

(** [hash template] creates a digest from a template.

    It sorts the elements of the template to be sure to have the
    same digest for two templates that have attributes in different
    orders. *)
val hash : t -> Digest.t

(** {2 Accessors }  *)

val get_class : t -> Pkcs11.CK_OBJECT_CLASS.u option
val get_key_type : t -> Pkcs11.CK_KEY_TYPE.u option
val get_label : t -> string option
