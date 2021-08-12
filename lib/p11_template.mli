type t = P11_attribute.pack list [@@deriving eq, ord, show, yojson]

val to_string : t -> string

val get : t -> 'a P11_attribute_type.t -> 'a option
(** Return the value of the first occurrence of an attribute. *)

val get_pack : t -> P11_attribute_type.pack -> P11_attribute.pack option

val mem : P11_attribute.pack -> t -> bool

val normalize : t -> t

val attribute_types : t -> P11_attribute_type.pack list

val set_attribute : P11_attribute.pack -> t -> t
(** [set_attribute attribute template] replaces the value of
    [attribute] in [template] if it already exists and adds
    [attribute] otherwise. *)

val remove_attribute : P11_attribute.pack -> t -> t
(** [remove_attribute attribute template] removes the value
    [attribute] from [template] if present. If the attribute_type of
    [attribute] is present with a different value, does nothing. *)

val remove_attribute_type : P11_attribute_type.pack -> t -> t
(** [remove_attribute attribute_type template] removes the attribute
    type [attribute_type] from [template] if present with any
    value. *)

val fold : ('a -> t -> t) -> 'a list -> t -> t
(** Iterate one of the above operation. Same as List.fold_right*)

val union : t -> t -> t
(** [union template1 template2] concatenates the templates. If an
    attribute is present in both [template1] and [template2], the
    value in [template1] is kept. *)

val only_attribute_types : P11_attribute_type.pack list -> t -> t
(** [only_attribute_types attr_types template] keeps only the
    attributes in [template] that are present in [attr_types]. *)

val except_attribute_types : P11_attribute_type.pack list -> t -> t
(** [except_attribute_types attr_types template] removes all the
    attributes in [template] that are present in [attr_types]. *)

val find_attribute_types : P11_attribute_type.pack list -> t -> t option
(** [find_attribute_types l template] look up for the value of each
    attribute type in the list l in [template]. Return [None] if one
    or several attribute types cannot be found in [template]. *)

val correspond : source:t -> tested:t -> bool
(** [correspond source tested] check if [tested] match
    [source].
    It means that it will return true if All the elements
    in [source] are present in [tested].
*)

val diff :
  source:t -> tested:t -> P11_attribute.pack list * P11_attribute.pack list
(** [diff source tested] search for all the elements of [source]
    that are not equal to an element of [tested].

    It returns a tuple with the list of elements from source
    which are expected but not found in tested and a list of elements
    which are found but with a different value.
*)

val hash : t -> Digest.t
(** [hash template] creates a digest from a template.

    It sorts the elements of the template to be sure to have the
    same digest for two templates that have attributes in different
    orders. *)

(** {2 Accessors }  *)

val get_class : t -> P11_object_class.t option

val get_key_type : t -> P11_key_type.t option

val get_label : t -> string option
