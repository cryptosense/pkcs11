(** Information about key types *)

(**
   The type of kinds that applies to a given object.
*)
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

(** Return all the possible attributes for a given kind, if the
    kind is a high level kind (Secret for example), it is possible
    that some other attribute can be given but not necessarily to all
    of the object of this kind. *)
val possibles : kind -> P11.Attribute_types.t

(** Return the list of kinds that are possible with this attribute.*)
val kinds : P11.Attribute_type.pack -> kind list

(** Check that an attribute_type could be used in all the kind present
    in the list.
    It means it is always possible to have this attribute with these kinds,
    If you give [KEA;Private] and an attribute_type that can't be used
    in every private key, it will return false.
*)
val is : kind list -> P11.Attribute_type.pack -> bool
