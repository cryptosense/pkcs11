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
  | `DSA_private
  | `DSA_public
  | `Secret
  ]

(** Return all the possible attributes for a given kind, if the
    kind is a high level kind (Secret for example), it is possible
    that some other attribute can be given but not necessarily to all
    of the object of this kind. *)
val possible : kind -> P11.Attribute_types.t
[@@deprecated]
