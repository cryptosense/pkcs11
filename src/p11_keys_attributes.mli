(** Information about key types *)

(**
   The type of kinds that applies to a given object.
*)
type kind =
  [
    | `Key
    | `Public
    | `Private
    | `Secret
    (* | `OTP (* V2.20 amendment 1 *) *)
    | `RSA_public
    | `RSA_private
    | `DSA_public
    | `DSA_private
    | `EC_public
    | `EC_private
    | `DH_public
    | `DH_private
    | `DH_X9_42_public
    | `DH_X9_42_private
    | `KEA_public
    | `KEA_private
    | `Generic_secret
    | `RC2
    | `RC4
    | `RC5
    | `AES
    | `DES
    | `CAST
    | `CAST3
    | `CAST128
    | `IDEA
    | `CDMF
    | `DES2
    | `DES3
    | `SKIPJACK
    | `BATON
    | `JUNIPER
    | `BLOWFISH
    | `TWOFISH
    (*
    | `CAMELLIA (* V2.20 amendment 3 *)
    | `ARIA (* V2.20 amendment 3 *)
    | `ACTI (* V2.20 amendment 1 *)
    | `SEED (* V2.30 *)
    | `SECURID (* V2.20 amendment 1 *)
    | `HOTP (* V2.20 amendment 1 *)
    | `GOST_28147_89 (* V2.30 *)
    | `GOST_R_34_10_2001_public (* V2.30 *)
    | `GOST_R_34_10_2001_private (* V2.30 *)
    *)
    | `VENDOR_DEFINED
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
