type t =
  | CKM_SHA_1
  | CKM_SHA224
  | CKM_SHA256
  | CKM_SHA384
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
  | CKM_AES_CBC of P11_hex_data.t
  | CKM_AES_CBC_PAD of P11_hex_data.t
  | CKM_AES_MAC
  | CKM_AES_MAC_GENERAL of P11_ulong.t
  | CKM_AES_ECB_ENCRYPT_DATA of P11_hex_data.t
  | CKM_AES_CBC_ENCRYPT_DATA of P11_aes_cbc_encrypt_data_params.t
  | CKM_DES_KEY_GEN
  | CKM_DES_ECB
  | CKM_DES_CBC of P11_hex_data.t
  | CKM_DES_CBC_PAD of P11_hex_data.t
  | CKM_DES_MAC
  | CKM_DES_MAC_GENERAL of P11_ulong.t
  | CKM_DES_ECB_ENCRYPT_DATA of P11_hex_data.t
  | CKM_DES_CBC_ENCRYPT_DATA of P11_des_cbc_encrypt_data_params.t
  | CKM_DES3_KEY_GEN
  | CKM_DES3_ECB
  | CKM_DES3_CBC of P11_hex_data.t
  | CKM_DES3_CBC_PAD of P11_hex_data.t
  | CKM_DES3_MAC
  | CKM_DES3_MAC_GENERAL of P11_ulong.t
  | CKM_DES3_ECB_ENCRYPT_DATA of P11_hex_data.t
  | CKM_DES3_CBC_ENCRYPT_DATA of P11_des_cbc_encrypt_data_params.t
  | CKM_CONCATENATE_BASE_AND_DATA of P11_hex_data.t
  | CKM_CONCATENATE_DATA_AND_BASE of P11_hex_data.t
  | CKM_XOR_BASE_AND_DATA of P11_hex_data.t
  | CKM_EXTRACT_KEY_FROM_KEY of P11_ulong.t
  | CKM_CONCATENATE_BASE_AND_KEY of P11_object_handle.t
  | CKM_EC_KEY_PAIR_GEN
  | CKM_ECDSA
  | CKM_ECDSA_SHA1
  | CKM_ECDSA_SHA224
  | CKM_ECDSA_SHA256
  | CKM_ECDSA_SHA384
  | CKM_ECDSA_SHA512
  | CKM_ECDH1_DERIVE of P11_ecdh1_derive_params.t
  | CKM_ECDH1_COFACTOR_DERIVE of P11_ecdh1_derive_params.t
  | CKM_ECMQV_DERIVE of P11_ecmqv_derive_params.t
  | CKM_PKCS5_PBKD2 of P11_pkcs5_pbkd2_data_params.t
  | CKM_DSA_KEY_PAIR_GEN
  | CKM_DSA_SHA1
  | CKM_DSA_SHA224
  | CKM_DSA_SHA256
  | CKM_DSA_SHA384
  | CKM_DSA_SHA512
  | CKM_AES_CTR of P11_aes_ctr_params.t
  | CKM_AES_GCM of P11_gcm_params.t
  | CKM_SHA_1_HMAC
  | CKM_SHA224_HMAC
  | CKM_SHA256_HMAC
  | CKM_SHA384_HMAC
  | CKM_SHA512_HMAC
  | CKM_GENERIC_SECRET_KEY_GEN
  | CKM_AES_KEY_WRAP of P11_aes_key_wrap_params.t
  | CKM_CS_UNKNOWN of P11_ulong.t
[@@deriving eq, ord, show, yojson]

val mechanism_type : t -> P11_mechanism_type.t

val to_string : t -> string
(** [to_string] is defined as [fun x -> Mechanism_type.to_string (mechanism_type x) ]  *)

val key_type : t -> P11_key_type.t option
(** [key_type t] returns the type of keys associated to the mechanism [t]. *)
