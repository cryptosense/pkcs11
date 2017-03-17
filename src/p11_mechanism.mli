type t = Pkcs11.CK_MECHANISM.u =
  | CKM_SHA_1
  | CKM_SHA224
  | CKM_SHA256
  | CKM_SHA512
  | CKM_MD5
  | CKM_RSA_PKCS_KEY_PAIR_GEN
  | CKM_RSA_X9_31_KEY_PAIR_GEN
  | CKM_RSA_PKCS
  | CKM_RSA_PKCS_OAEP of P11_rsa_pkcs_oaep_params.t
  | CKM_RSA_X_509
  | CKM_RSA_PKCS_PSS of P11_rsa_pkcs_pss_params.t
  | CKM_SHA1_RSA_PKCS
  | CKM_SHA224_RSA_PKCS
  | CKM_SHA256_RSA_PKCS
  | CKM_SHA384_RSA_PKCS
  | CKM_SHA512_RSA_PKCS
  | CKM_SHA1_RSA_PKCS_PSS of P11_rsa_pkcs_pss_params.t
  | CKM_SHA224_RSA_PKCS_PSS of P11_rsa_pkcs_pss_params.t
  | CKM_SHA256_RSA_PKCS_PSS of P11_rsa_pkcs_pss_params.t
  | CKM_SHA384_RSA_PKCS_PSS of P11_rsa_pkcs_pss_params.t
  | CKM_SHA512_RSA_PKCS_PSS of P11_rsa_pkcs_pss_params.t
  | CKM_AES_KEY_GEN
  | CKM_AES_ECB
  | CKM_AES_CBC of Pkcs11_hex_data.t
  | CKM_AES_CBC_PAD of Pkcs11_hex_data.t
  | CKM_AES_MAC
  | CKM_AES_MAC_GENERAL of Pkcs11_CK_ULONG.t
  | CKM_AES_ECB_ENCRYPT_DATA of Pkcs11_hex_data.t
  | CKM_AES_CBC_ENCRYPT_DATA of P11_aes_cbc_encrypt_data_params.t
  | CKM_DES_KEY_GEN
  | CKM_DES_ECB
  | CKM_DES_CBC of Pkcs11_hex_data.t
  | CKM_DES_CBC_PAD of Pkcs11_hex_data.t
  | CKM_DES_MAC
  | CKM_DES_MAC_GENERAL of Pkcs11_CK_ULONG.t
  | CKM_DES_ECB_ENCRYPT_DATA of Pkcs11_hex_data.t
  | CKM_DES_CBC_ENCRYPT_DATA of P11_des_cbc_encrypt_data_params.t
  | CKM_DES3_KEY_GEN
  | CKM_DES3_ECB
  | CKM_DES3_CBC of Pkcs11_hex_data.t
  | CKM_DES3_CBC_PAD of Pkcs11_hex_data.t
  | CKM_DES3_MAC
  | CKM_DES3_MAC_GENERAL of Pkcs11_CK_ULONG.t
  | CKM_DES3_ECB_ENCRYPT_DATA of Pkcs11_hex_data.t
  | CKM_DES3_CBC_ENCRYPT_DATA of P11_des_cbc_encrypt_data_params.t
  | CKM_CONCATENATE_BASE_AND_DATA of Pkcs11_hex_data.t
  | CKM_CONCATENATE_DATA_AND_BASE of Pkcs11_hex_data.t
  | CKM_XOR_BASE_AND_DATA of Pkcs11_hex_data.t
  | CKM_EXTRACT_KEY_FROM_KEY of Pkcs11_CK_ULONG.t
  | CKM_CONCATENATE_BASE_AND_KEY of P11_object_handle.t
  | CKM_EC_KEY_PAIR_GEN
  | CKM_ECDSA
  | CKM_ECDSA_SHA1
  | CKM_ECDH1_DERIVE of Pkcs11.CK_ECDH1_DERIVE_PARAMS.u
  | CKM_ECDH1_COFACTOR_DERIVE of Pkcs11.CK_ECDH1_DERIVE_PARAMS.u
  | CKM_ECMQV_DERIVE of Pkcs11.CK_ECMQV_DERIVE_PARAMS.u
  | CKM_PKCS5_PBKD2 of P11_pkcs5_pbkd2_data_params.t
  | CKM_CS_UNKNOWN of P11_raw_payload_params.t
  [@@deriving yojson]

val mechanism_type: t -> P11_mechanism_type.t
val compare: t -> t -> int

(** [to_string] is defined as [fun x -> Mechanism_type.to_string (mechanism_type x) ]  *)
val to_string : t -> string

val pp : Format.formatter -> t -> unit

val of_raw : Pkcs11.CK_MECHANISM.t -> t

(** Kinds are "tags" on mechanisms which describe how they can be
    used. *)
type kind =
  | Encrypt                     (* Encrypt & Decrypt *)
  | Sign                        (* Sign & Verify *)
  | SignRecover                 (* Sign Recover & Verify recover *)
  | Wrap                        (* Wrap & Unwrap *)
  | Derive
  | Digest
  | Generate                    (* GenerateKey or GenerateKeypair *)


  | Symmetric
  | Asymmetric

  | DES
  | DES3
  | AES
  | RSA
  | DH
  | EC



  (** [kinds mechanism] returns the tags for the mechanism
    [mechanism].  *)
val kinds : t -> kind list

(** [is kinds t] checks that the mechanism [t] has all the tags in
    the list [kinds].  *)
val is: kind list -> t -> bool

(** [key_type t] returns the type of keys associated to the mechanism [t]. *)
val key_type: t -> P11_key_type.t option
