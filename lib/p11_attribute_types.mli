type t = P11_attribute_type.pack list
[@@deriving eq,ord,show,yojson]

(** Return true if an attribute_type is present in an attribute_type list. *)
val mem : t -> 'a P11_attribute_type.t -> bool

(** Remove the duplicates from a list of attribute types *)
val remove_duplicates : t -> t
