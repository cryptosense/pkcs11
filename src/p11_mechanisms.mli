(** Information about mechanisms *)

(** The type of kinds that applies to a given mechanism. There are two
    flavor of kinds: kinds that come from the standard (in particular
    table 34 of v2.20); and tags that we apply to groups of mechanisms.  *)
type kind =
  (* kinds from the standard *)
  | Encrypt                     (* Encrypt & Decrypt *)
  | Sign                        (* Sign & Verify *)
  | SignRecover                 (* Sign Recover & Verify recover *)
  | Wrap                        (* Wrap & Unwrap *)
  | Derive
  | Digest
  | Generate                    (* GenerateKey or GenerateKeypair *)


  | Symmetric
  | Asymmetric

  (* The following tags are informative only. To get the key type
     associated with a given mechanism, use the [key_type] function
     below. *)
  | DES
  | DES3
  | AES
  | RSA
  | DH
  | EC
  (* todo: V2_20, V2_30, V2_40?  *)

(** Return the list of kinds that are defined for a mechanism. The
    list may be empty. *)
val kinds: Pkcs11.CK_MECHANISM_TYPE.u -> kind list

(** Checks that a mechanism as *all* the kinds present in the list. *)
val is:  kind list -> Pkcs11.CK_MECHANISM_TYPE.u -> bool


(** Support missing for a given mechanism in [key_type].  *)
exception Mechanism_not_supported of string

(** Return the key type associated to a given mechanism. May raise
    [Mechanism_not_supported] because the implementation of [key_type]
    is partial. Some mechanisms do not have associated key types
    (e.g., hash algorithms). *)
val key_type: Pkcs11.CK_MECHANISM_TYPE.u -> Pkcs11.CK_KEY_TYPE.u option
