type t = P11_attribute_type.pack list [@@deriving eq, ord, show, yojson]

val mem : t -> 'a P11_attribute_type.t -> bool
(** Return true if an attribute_type is present in an attribute_type list. *)

val remove_duplicates : t -> t
(** Remove the duplicates from a list of attribute types *)
