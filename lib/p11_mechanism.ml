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
[@@deriving eq, ord, show]

let to_json =
  let simple name = `String name in
  let param name param json_of_param = `Assoc [(name, json_of_param param)] in
  let ulong name p = param name p P11_ulong.to_yojson in
  function
  | CKM_SHA_1 -> simple "CKM_SHA_1"
  | CKM_SHA224 -> simple "CKM_SHA224"
  | CKM_SHA256 -> simple "CKM_SHA256"
  | CKM_SHA384 -> simple "CKM_SHA384"
  | CKM_SHA512 -> simple "CKM_SHA512"
  | CKM_MD5 -> simple "CKM_MD5"
  | CKM_RSA_PKCS_KEY_PAIR_GEN -> simple "CKM_RSA_PKCS_KEY_PAIR_GEN"
  | CKM_RSA_X9_31_KEY_PAIR_GEN -> simple "CKM_RSA_X9_31_KEY_PAIR_GEN"
  | CKM_RSA_PKCS -> simple "CKM_RSA_PKCS"
  | CKM_RSA_PKCS_OAEP p ->
    param "CKM_RSA_PKCS_OAEP" p P11_rsa_pkcs_oaep_params.to_yojson
  | CKM_RSA_X_509 -> simple "CKM_RSA_X_509"
  | CKM_RSA_PKCS_PSS p ->
    param "CKM_RSA_PKCS_PSS" p P11_rsa_pkcs_pss_params.to_yojson
  | CKM_SHA1_RSA_PKCS -> simple "CKM_SHA1_RSA_PKCS"
  | CKM_SHA224_RSA_PKCS -> simple "CKM_SHA224_RSA_PKCS"
  | CKM_SHA256_RSA_PKCS -> simple "CKM_SHA256_RSA_PKCS"
  | CKM_SHA384_RSA_PKCS -> simple "CKM_SHA384_RSA_PKCS"
  | CKM_SHA512_RSA_PKCS -> simple "CKM_SHA512_RSA_PKCS"
  | CKM_SHA1_RSA_PKCS_PSS p ->
    param "CKM_SHA1_RSA_PKCS_PSS" p P11_rsa_pkcs_pss_params.to_yojson
  | CKM_SHA224_RSA_PKCS_PSS p ->
    param "CKM_SHA224_RSA_PKCS_PSS" p P11_rsa_pkcs_pss_params.to_yojson
  | CKM_SHA256_RSA_PKCS_PSS p ->
    param "CKM_SHA256_RSA_PKCS_PSS" p P11_rsa_pkcs_pss_params.to_yojson
  | CKM_SHA384_RSA_PKCS_PSS p ->
    param "CKM_SHA384_RSA_PKCS_PSS" p P11_rsa_pkcs_pss_params.to_yojson
  | CKM_SHA512_RSA_PKCS_PSS p ->
    param "CKM_SHA512_RSA_PKCS_PSS" p P11_rsa_pkcs_pss_params.to_yojson
  | CKM_AES_KEY_GEN -> simple "CKM_AES_KEY_GEN"
  | CKM_AES_ECB -> simple "CKM_AES_ECB"
  | CKM_AES_CBC p -> param "CKM_AES_CBC" p P11_hex_data.to_yojson
  | CKM_AES_CBC_PAD p -> param "CKM_AES_CBC_PAD" p P11_hex_data.to_yojson
  | CKM_AES_MAC -> simple "CKM_AES_MAC"
  | CKM_AES_MAC_GENERAL p -> ulong "CKM_AES_MAC_GENERAL" p
  | CKM_AES_ECB_ENCRYPT_DATA p ->
    param "CKM_AES_ECB_ENCRYPT_DATA" p P11_hex_data.to_yojson
  | CKM_AES_CBC_ENCRYPT_DATA p ->
    param "CKM_AES_CBC_ENCRYPT_DATA" p P11_aes_cbc_encrypt_data_params.to_yojson
  | CKM_DES_KEY_GEN -> simple "CKM_DES_KEY_GEN"
  | CKM_DES_ECB -> simple "CKM_DES_ECB"
  | CKM_DES_CBC p -> param "CKM_DES_CBC" p P11_hex_data.to_yojson
  | CKM_DES_CBC_PAD p -> param "CKM_DES_CBC_PAD" p P11_hex_data.to_yojson
  | CKM_DES_MAC -> simple "CKM_DES_MAC"
  | CKM_DES_MAC_GENERAL p -> ulong "CKM_DES_MAC_GENERAL" p
  | CKM_DES_ECB_ENCRYPT_DATA p ->
    param "CKM_DES_ECB_ENCRYPT_DATA" p P11_hex_data.to_yojson
  | CKM_DES_CBC_ENCRYPT_DATA p ->
    param "CKM_DES_CBC_ENCRYPT_DATA" p P11_des_cbc_encrypt_data_params.to_yojson
  | CKM_DES3_KEY_GEN -> simple "CKM_DES3_KEY_GEN"
  | CKM_DES3_ECB -> simple "CKM_DES3_ECB"
  | CKM_DES3_CBC p -> param "CKM_DES3_CBC" p P11_hex_data.to_yojson
  | CKM_DES3_CBC_PAD p -> param "CKM_DES3_CBC_PAD" p P11_hex_data.to_yojson
  | CKM_DES3_MAC -> simple "CKM_DES3_MAC"
  | CKM_DES3_MAC_GENERAL p -> ulong "CKM_DES3_MAC_GENERAL" p
  | CKM_DES3_ECB_ENCRYPT_DATA p ->
    param "CKM_DES3_ECB_ENCRYPT_DATA" p P11_hex_data.to_yojson
  | CKM_DES3_CBC_ENCRYPT_DATA p ->
    param "CKM_DES3_CBC_ENCRYPT_DATA" p
      P11_des_cbc_encrypt_data_params.to_yojson
  | CKM_CONCATENATE_BASE_AND_DATA p ->
    param "CKM_CONCATENATE_BASE_AND_DATA" p P11_hex_data.to_yojson
  | CKM_CONCATENATE_DATA_AND_BASE p ->
    param "CKM_CONCATENATE_DATA_AND_BASE" p P11_hex_data.to_yojson
  | CKM_XOR_BASE_AND_DATA p ->
    param "CKM_XOR_BASE_AND_DATA" p P11_hex_data.to_yojson
  | CKM_EXTRACT_KEY_FROM_KEY p -> ulong "CKM_EXTRACT_KEY_FROM_KEY" p
  | CKM_CONCATENATE_BASE_AND_KEY p ->
    param "CKM_CONCATENATE_BASE_AND_KEY" p P11_object_handle.to_yojson
  | CKM_EC_KEY_PAIR_GEN -> simple "CKM_EC_KEY_PAIR_GEN"
  | CKM_ECDSA -> simple "CKM_ECDSA"
  | CKM_ECDSA_SHA1 -> simple "CKM_ECDSA_SHA1"
  | CKM_ECDSA_SHA224 -> simple "CKM_ECDSA_SHA224"
  | CKM_ECDSA_SHA256 -> simple "CKM_ECDSA_SHA256"
  | CKM_ECDSA_SHA384 -> simple "CKM_ECDSA_SHA384"
  | CKM_ECDSA_SHA512 -> simple "CKM_ECDSA_SHA512"
  | CKM_ECDH1_DERIVE p ->
    param "CKM_ECDH1_DERIVE" p P11_ecdh1_derive_params.to_yojson
  | CKM_ECDH1_COFACTOR_DERIVE p ->
    param "CKM_ECDH1_COFACTOR_DERIVE" p P11_ecdh1_derive_params.to_yojson
  | CKM_ECMQV_DERIVE p ->
    param "CKM_ECMQV_DERIVE" p P11_ecmqv_derive_params.to_yojson
  | CKM_PKCS5_PBKD2 p ->
    param "CKM_PKCS5_PBKD2" p P11_pkcs5_pbkd2_data_params.to_yojson
  | CKM_DSA_KEY_PAIR_GEN -> simple "CKM_DSA_KEY_PAIR_GEN"
  | CKM_DSA_SHA1 -> simple "CKM_DSA_SHA1"
  | CKM_DSA_SHA224 -> simple "CKM_DSA_SHA224"
  | CKM_DSA_SHA256 -> simple "CKM_DSA_SHA256"
  | CKM_DSA_SHA384 -> simple "CKM_DSA_SHA384"
  | CKM_DSA_SHA512 -> simple "CKM_DSA_SHA512"
  | CKM_AES_CTR p -> param "CKM_AES_CTR" p P11_aes_ctr_params.to_yojson
  | CKM_AES_GCM p -> param "CKM_AES_GCM" p P11_gcm_params.to_yojson
  | CKM_SHA_1_HMAC -> simple "CKM_SHA_1_HMAC"
  | CKM_SHA224_HMAC -> simple "CKM_SHA224_HMAC"
  | CKM_SHA256_HMAC -> simple "CKM_SHA256_HMAC"
  | CKM_SHA384_HMAC -> simple "CKM_SHA384_HMAC"
  | CKM_SHA512_HMAC -> simple "CKM_SHA512_HMAC"
  | CKM_GENERIC_SECRET_KEY_GEN -> simple "CKM_GENERIC_SECRET_KEY_GEN"
  | CKM_AES_KEY_WRAP p ->
    param "CKM_AES_KEY_WRAP" p P11_aes_key_wrap_params.to_yojson
  | CKM_CS_UNKNOWN p -> param "CKM_NOT_IMPLEMENTED" p P11_ulong.to_yojson

let of_yojson json =
  let parse name param =
    let simple ckm =
      if param = `Null then
        Ok ckm
      else
        Error "Mechanism does not expect a parameter"
    in
    let open Ppx_deriving_yojson_runtime in
    let oaep make =
      P11_rsa_pkcs_oaep_params.of_yojson param >>= fun r -> Ok (make r)
    in
    let pbkd2 make =
      P11_pkcs5_pbkd2_data_params.of_yojson param >>= fun r -> Ok (make r)
    in
    let pss make =
      P11_rsa_pkcs_pss_params.of_yojson param >>= fun r -> Ok (make r)
    in
    let data make = P11_hex_data.of_yojson param >>= fun r -> Ok (make r) in
    match name with
    | "CKM_SHA_1" -> simple CKM_SHA_1
    | "CKM_SHA224" -> simple CKM_SHA224
    | "CKM_SHA256" -> simple CKM_SHA256
    | "CKM_SHA384" -> simple CKM_SHA384
    | "CKM_SHA512" -> simple CKM_SHA512
    | "CKM_MD5" -> simple CKM_MD5
    | "CKM_RSA_PKCS_KEY_PAIR_GEN" -> simple CKM_RSA_PKCS_KEY_PAIR_GEN
    | "CKM_RSA_X9_31_KEY_PAIR_GEN" -> simple CKM_RSA_X9_31_KEY_PAIR_GEN
    | "CKM_RSA_PKCS" -> simple CKM_RSA_PKCS
    | "CKM_RSA_PKCS_OAEP" -> oaep (fun x -> CKM_RSA_PKCS_OAEP x)
    | "CKM_PKCS5_PBKD2" -> pbkd2 (fun x -> CKM_PKCS5_PBKD2 x)
    | "CKM_RSA_X_509" -> simple CKM_RSA_X_509
    | "CKM_RSA_PKCS_PSS" -> pss (fun x -> CKM_RSA_PKCS_PSS x)
    | "CKM_SHA1_RSA_PKCS" -> simple CKM_SHA1_RSA_PKCS
    | "CKM_SHA224_RSA_PKCS" -> simple CKM_SHA224_RSA_PKCS
    | "CKM_SHA256_RSA_PKCS" -> simple CKM_SHA256_RSA_PKCS
    | "CKM_SHA384_RSA_PKCS" -> simple CKM_SHA384_RSA_PKCS
    | "CKM_SHA512_RSA_PKCS" -> simple CKM_SHA512_RSA_PKCS
    | "CKM_SHA1_RSA_PKCS_PSS" -> pss (fun x -> CKM_SHA1_RSA_PKCS_PSS x)
    | "CKM_SHA224_RSA_PKCS_PSS" -> pss (fun x -> CKM_SHA224_RSA_PKCS_PSS x)
    | "CKM_SHA256_RSA_PKCS_PSS" -> pss (fun x -> CKM_SHA256_RSA_PKCS_PSS x)
    | "CKM_SHA384_RSA_PKCS_PSS" -> pss (fun x -> CKM_SHA384_RSA_PKCS_PSS x)
    | "CKM_SHA512_RSA_PKCS_PSS" -> pss (fun x -> CKM_SHA512_RSA_PKCS_PSS x)
    | "CKM_AES_KEY_GEN" -> simple CKM_AES_KEY_GEN
    | "CKM_AES_ECB" -> simple CKM_AES_ECB
    | "CKM_AES_CBC" -> data (fun x -> CKM_AES_CBC x)
    | "CKM_AES_CBC_PAD" -> data (fun x -> CKM_AES_CBC_PAD x)
    | "CKM_AES_MAC" -> simple CKM_AES_MAC
    | "CKM_AES_MAC_GENERAL" ->
      P11_ulong.of_yojson param >>= fun r -> Ok (CKM_AES_MAC_GENERAL r)
    | "CKM_AES_ECB_ENCRYPT_DATA" -> data (fun x -> CKM_AES_ECB_ENCRYPT_DATA x)
    | "CKM_AES_CBC_ENCRYPT_DATA" ->
      P11_aes_cbc_encrypt_data_params.of_yojson param >>= fun r ->
      Ok (CKM_AES_CBC_ENCRYPT_DATA r)
    | "CKM_DES_KEY_GEN" -> simple CKM_DES_KEY_GEN
    | "CKM_DES_ECB" -> simple CKM_DES_ECB
    | "CKM_DES_CBC" -> data (fun x -> CKM_DES_CBC x)
    | "CKM_DES_CBC_PAD" -> data (fun x -> CKM_DES_CBC_PAD x)
    | "CKM_DES_MAC" -> simple CKM_DES_MAC
    | "CKM_DES_MAC_GENERAL" ->
      P11_ulong.of_yojson param >>= fun r -> Ok (CKM_DES_MAC_GENERAL r)
    | "CKM_DES_ECB_ENCRYPT_DATA" -> data (fun x -> CKM_DES_ECB_ENCRYPT_DATA x)
    | "CKM_DES_CBC_ENCRYPT_DATA" ->
      P11_des_cbc_encrypt_data_params.of_yojson param >>= fun r ->
      Ok (CKM_DES_CBC_ENCRYPT_DATA r)
    | "CKM_DES3_KEY_GEN" -> simple CKM_DES3_KEY_GEN
    | "CKM_DES3_ECB" -> simple CKM_DES3_ECB
    | "CKM_DES3_CBC" -> data (fun x -> CKM_DES3_CBC x)
    | "CKM_DES3_CBC_PAD" -> data (fun x -> CKM_DES3_CBC_PAD x)
    | "CKM_DES3_MAC" -> simple CKM_DES3_MAC
    | "CKM_DES3_MAC_GENERAL" ->
      P11_ulong.of_yojson param >>= fun r -> Ok (CKM_DES3_MAC_GENERAL r)
    | "CKM_DES3_ECB_ENCRYPT_DATA" -> data (fun x -> CKM_DES3_ECB_ENCRYPT_DATA x)
    | "CKM_DES3_CBC_ENCRYPT_DATA" ->
      P11_des_cbc_encrypt_data_params.of_yojson param >>= fun r ->
      Ok (CKM_DES3_CBC_ENCRYPT_DATA r)
    | "CKM_CONCATENATE_BASE_AND_DATA" ->
      data (fun x -> CKM_CONCATENATE_BASE_AND_DATA x)
    | "CKM_CONCATENATE_DATA_AND_BASE" ->
      data (fun x -> CKM_CONCATENATE_DATA_AND_BASE x)
    | "CKM_XOR_BASE_AND_DATA" -> data (fun x -> CKM_XOR_BASE_AND_DATA x)
    | "CKM_EXTRACT_KEY_FROM_KEY" ->
      P11_ulong.of_yojson param >>= fun r -> Ok (CKM_EXTRACT_KEY_FROM_KEY r)
    | "CKM_CONCATENATE_BASE_AND_KEY" ->
      P11_object_handle.of_yojson param >>= fun r ->
      Ok (CKM_CONCATENATE_BASE_AND_KEY r)
    | "CKM_EC_KEY_PAIR_GEN" -> simple CKM_EC_KEY_PAIR_GEN
    | "CKM_ECDSA" -> simple CKM_ECDSA
    | "CKM_ECDSA_SHA1" -> simple CKM_ECDSA_SHA1
    | "CKM_ECDSA_SHA224" -> simple CKM_ECDSA_SHA224
    | "CKM_ECDSA_SHA256" -> simple CKM_ECDSA_SHA256
    | "CKM_ECDSA_SHA384" -> simple CKM_ECDSA_SHA384
    | "CKM_ECDSA_SHA512" -> simple CKM_ECDSA_SHA512
    | "CKM_ECDH1_DERIVE" ->
      P11_ecdh1_derive_params.of_yojson param >>= fun r ->
      Ok (CKM_ECDH1_DERIVE r)
    | "CKM_AES_CTR" ->
      P11_aes_ctr_params.of_yojson param >>= fun r -> Ok (CKM_AES_CTR r)
    | "CKM_AES_GCM" ->
      P11_gcm_params.of_yojson param >>= fun r -> Ok (CKM_AES_GCM r)
    | "CKM_DSA_KEY_PAIR_GEN" -> simple CKM_DSA_KEY_PAIR_GEN
    | "CKM_DSA_SHA1" -> simple CKM_DSA_SHA1
    | "CKM_DSA_SHA224" -> simple CKM_DSA_SHA224
    | "CKM_DSA_SHA256" -> simple CKM_DSA_SHA256
    | "CKM_DSA_SHA384" -> simple CKM_DSA_SHA384
    | "CKM_DSA_SHA512" -> simple CKM_DSA_SHA512
    | "CKM_SHA_1_HMAC" -> simple CKM_SHA_1_HMAC
    | "CKM_SHA224_HMAC" -> simple CKM_SHA224_HMAC
    | "CKM_SHA256_HMAC" -> simple CKM_SHA256_HMAC
    | "CKM_SHA384_HMAC" -> simple CKM_SHA384_HMAC
    | "CKM_SHA512_HMAC" -> simple CKM_SHA512_HMAC
    | "CKM_GENERIC_SECRET_KEY_GEN" -> simple CKM_GENERIC_SECRET_KEY_GEN
    | "CKM_AES_KEY_WRAP" ->
      P11_aes_key_wrap_params.of_yojson param >>= fun r ->
      Ok (CKM_AES_KEY_WRAP r)
    | _ ->
      P11_ulong.of_yojson param >>= fun params -> Ok (CKM_CS_UNKNOWN params)
  in
  match json with
  | `Assoc [(name, param)] -> parse name param
  | `String name -> parse name `Null
  | _ -> Error "Ill-formed mechanism"

let to_yojson = to_json

let mechanism_type m =
  let module T = P11_mechanism_type in
  match m with
  | CKM_SHA_1 -> T.CKM_SHA_1
  | CKM_SHA224 -> T.CKM_SHA224
  | CKM_SHA256 -> T.CKM_SHA256
  | CKM_SHA384 -> T.CKM_SHA384
  | CKM_SHA512 -> T.CKM_SHA512
  | CKM_MD5 -> T.CKM_MD5
  | CKM_RSA_PKCS_KEY_PAIR_GEN -> T.CKM_RSA_PKCS_KEY_PAIR_GEN
  | CKM_RSA_X9_31_KEY_PAIR_GEN -> T.CKM_RSA_X9_31_KEY_PAIR_GEN
  | CKM_RSA_PKCS -> T.CKM_RSA_PKCS
  | CKM_RSA_PKCS_OAEP _ -> T.CKM_RSA_PKCS_OAEP
  | CKM_RSA_X_509 -> T.CKM_RSA_X_509
  | CKM_RSA_PKCS_PSS _ -> T.CKM_RSA_PKCS_PSS
  | CKM_SHA1_RSA_PKCS -> T.CKM_SHA1_RSA_PKCS
  | CKM_SHA224_RSA_PKCS -> T.CKM_SHA224_RSA_PKCS
  | CKM_SHA256_RSA_PKCS -> T.CKM_SHA256_RSA_PKCS
  | CKM_SHA384_RSA_PKCS -> T.CKM_SHA384_RSA_PKCS
  | CKM_SHA512_RSA_PKCS -> T.CKM_SHA512_RSA_PKCS
  | CKM_SHA1_RSA_PKCS_PSS _ -> T.CKM_SHA1_RSA_PKCS_PSS
  | CKM_SHA224_RSA_PKCS_PSS _ -> T.CKM_SHA224_RSA_PKCS_PSS
  | CKM_SHA256_RSA_PKCS_PSS _ -> T.CKM_SHA256_RSA_PKCS_PSS
  | CKM_SHA384_RSA_PKCS_PSS _ -> T.CKM_SHA384_RSA_PKCS_PSS
  | CKM_SHA512_RSA_PKCS_PSS _ -> T.CKM_SHA512_RSA_PKCS_PSS
  | CKM_AES_KEY_GEN -> T.CKM_AES_KEY_GEN
  | CKM_AES_ECB -> T.CKM_AES_ECB
  | CKM_AES_CBC _ -> T.CKM_AES_CBC
  | CKM_AES_CBC_PAD _ -> T.CKM_AES_CBC_PAD
  | CKM_AES_MAC -> T.CKM_AES_MAC
  | CKM_AES_MAC_GENERAL _ -> T.CKM_AES_MAC_GENERAL
  | CKM_AES_ECB_ENCRYPT_DATA _ -> T.CKM_AES_ECB_ENCRYPT_DATA
  | CKM_AES_CBC_ENCRYPT_DATA _ -> T.CKM_AES_CBC_ENCRYPT_DATA
  | CKM_DES_KEY_GEN -> T.CKM_DES_KEY_GEN
  | CKM_DES_ECB -> T.CKM_DES_ECB
  | CKM_DES_CBC _ -> T.CKM_DES_CBC
  | CKM_DES_CBC_PAD _ -> T.CKM_DES_CBC_PAD
  | CKM_DES_MAC -> T.CKM_DES_MAC
  | CKM_DES_MAC_GENERAL _ -> T.CKM_DES_MAC_GENERAL
  | CKM_DES_ECB_ENCRYPT_DATA _ -> T.CKM_DES_ECB_ENCRYPT_DATA
  | CKM_DES_CBC_ENCRYPT_DATA _ -> T.CKM_DES_CBC_ENCRYPT_DATA
  | CKM_DES3_KEY_GEN -> T.CKM_DES3_KEY_GEN
  | CKM_DES3_ECB -> T.CKM_DES3_ECB
  | CKM_DES3_CBC _ -> T.CKM_DES3_CBC
  | CKM_DES3_CBC_PAD _ -> T.CKM_DES3_CBC_PAD
  | CKM_DES3_MAC -> T.CKM_DES3_MAC
  | CKM_DES3_MAC_GENERAL _ -> T.CKM_DES3_MAC_GENERAL
  | CKM_DES3_ECB_ENCRYPT_DATA _ -> T.CKM_DES3_ECB_ENCRYPT_DATA
  | CKM_DES3_CBC_ENCRYPT_DATA _ -> T.CKM_DES3_CBC_ENCRYPT_DATA
  | CKM_CONCATENATE_BASE_AND_DATA _ -> T.CKM_CONCATENATE_BASE_AND_DATA
  | CKM_CONCATENATE_DATA_AND_BASE _ -> T.CKM_CONCATENATE_DATA_AND_BASE
  | CKM_XOR_BASE_AND_DATA _ -> T.CKM_XOR_BASE_AND_DATA
  | CKM_EXTRACT_KEY_FROM_KEY _ -> T.CKM_EXTRACT_KEY_FROM_KEY
  | CKM_CONCATENATE_BASE_AND_KEY _ -> T.CKM_CONCATENATE_BASE_AND_KEY
  | CKM_EC_KEY_PAIR_GEN -> T.CKM_EC_KEY_PAIR_GEN
  | CKM_ECDSA -> T.CKM_ECDSA
  | CKM_ECDSA_SHA1 -> T.CKM_ECDSA_SHA1
  | CKM_ECDSA_SHA224 -> T.CKM_ECDSA_SHA224
  | CKM_ECDSA_SHA256 -> T.CKM_ECDSA_SHA256
  | CKM_ECDSA_SHA384 -> T.CKM_ECDSA_SHA384
  | CKM_ECDSA_SHA512 -> T.CKM_ECDSA_SHA512
  | CKM_ECDH1_DERIVE _ -> T.CKM_ECDH1_DERIVE
  | CKM_ECDH1_COFACTOR_DERIVE _ -> T.CKM_ECDH1_COFACTOR_DERIVE
  | CKM_ECMQV_DERIVE _ -> T.CKM_ECMQV_DERIVE
  | CKM_PKCS5_PBKD2 _ -> T.CKM_PKCS5_PBKD2
  | CKM_DSA_KEY_PAIR_GEN -> T.CKM_DSA_KEY_PAIR_GEN
  | CKM_DSA_SHA1 -> T.CKM_DSA_SHA1
  | CKM_DSA_SHA224 -> T.CKM_DSA_SHA224
  | CKM_DSA_SHA256 -> T.CKM_DSA_SHA256
  | CKM_DSA_SHA384 -> T.CKM_DSA_SHA384
  | CKM_DSA_SHA512 -> T.CKM_DSA_SHA512
  | CKM_AES_CTR _ -> T.CKM_AES_CTR
  | CKM_AES_GCM _ -> T.CKM_AES_GCM
  | CKM_SHA_1_HMAC -> T.CKM_SHA_1_HMAC
  | CKM_SHA224_HMAC -> T.CKM_SHA224_HMAC
  | CKM_SHA256_HMAC -> T.CKM_SHA256_HMAC
  | CKM_SHA384_HMAC -> T.CKM_SHA384_HMAC
  | CKM_SHA512_HMAC -> T.CKM_SHA512_HMAC
  | CKM_GENERIC_SECRET_KEY_GEN -> T.CKM_GENERIC_SECRET_KEY_GEN
  | CKM_AES_KEY_WRAP _ -> T.CKM_AES_KEY_WRAP
  | CKM_CS_UNKNOWN mechanism_type -> T.CKM_CS_UNKNOWN mechanism_type

let key_type = function
  | CKM_AES_KEY_GEN
  | CKM_AES_ECB
  | CKM_AES_CBC _
  | CKM_AES_CBC_PAD _
  | CKM_AES_MAC
  | CKM_AES_MAC_GENERAL _
  | CKM_AES_ECB_ENCRYPT_DATA _
  | CKM_AES_CBC_ENCRYPT_DATA _
  | CKM_AES_CTR _
  | CKM_AES_GCM _
  | CKM_AES_KEY_WRAP _ ->
    Some P11_key_type.CKK_AES
  | CKM_DES_KEY_GEN
  | CKM_DES_ECB
  | CKM_DES_CBC _
  | CKM_DES_CBC_PAD _
  | CKM_DES_MAC
  | CKM_DES_MAC_GENERAL _
  | CKM_DES_ECB_ENCRYPT_DATA _
  | CKM_DES_CBC_ENCRYPT_DATA _ ->
    Some P11_key_type.CKK_DES
  | CKM_DES3_KEY_GEN
  | CKM_DES3_ECB
  | CKM_DES3_CBC _
  | CKM_DES3_CBC_PAD _
  | CKM_DES3_MAC
  | CKM_DES3_MAC_GENERAL _
  | CKM_DES3_ECB_ENCRYPT_DATA _
  | CKM_DES3_CBC_ENCRYPT_DATA _ ->
    Some P11_key_type.CKK_DES3
  | CKM_RSA_PKCS_KEY_PAIR_GEN
  | CKM_RSA_PKCS
  | CKM_RSA_X_509
  | CKM_RSA_PKCS_OAEP _
  | CKM_RSA_PKCS_PSS _
  | CKM_SHA1_RSA_PKCS
  | CKM_SHA224_RSA_PKCS
  | CKM_SHA256_RSA_PKCS
  | CKM_SHA384_RSA_PKCS
  | CKM_SHA512_RSA_PKCS
  | CKM_SHA1_RSA_PKCS_PSS _
  | CKM_SHA224_RSA_PKCS_PSS _
  | CKM_SHA256_RSA_PKCS_PSS _
  | CKM_SHA384_RSA_PKCS_PSS _
  | CKM_SHA512_RSA_PKCS_PSS _ ->
    Some P11_key_type.CKK_RSA
  | CKM_RSA_X9_31_KEY_PAIR_GEN -> Some P11_key_type.CKK_RSA
  | CKM_EC_KEY_PAIR_GEN
  | CKM_ECDSA
  | CKM_ECDSA_SHA1
  | CKM_ECDSA_SHA224
  | CKM_ECDSA_SHA256
  | CKM_ECDSA_SHA384
  | CKM_ECDSA_SHA512
  | CKM_ECDH1_DERIVE _
  | CKM_ECDH1_COFACTOR_DERIVE _
  | CKM_ECMQV_DERIVE _ ->
    Some P11_key_type.CKK_EC
  | CKM_DSA_KEY_PAIR_GEN
  | CKM_DSA_SHA1
  | CKM_DSA_SHA224
  | CKM_DSA_SHA256
  | CKM_DSA_SHA384
  | CKM_DSA_SHA512 ->
    Some P11_key_type.CKK_DSA
  | CKM_SHA_1_HMAC
  | CKM_SHA224_HMAC
  | CKM_SHA256_HMAC
  | CKM_SHA384_HMAC
  | CKM_SHA512_HMAC
  | CKM_GENERIC_SECRET_KEY_GEN ->
    Some P11_key_type.CKK_GENERIC_SECRET
  | CKM_SHA_1
  | CKM_SHA224
  | CKM_SHA256
  | CKM_SHA384
  | CKM_SHA512
  | CKM_MD5
  | CKM_CONCATENATE_BASE_AND_DATA _
  | CKM_CONCATENATE_DATA_AND_BASE _
  | CKM_EXTRACT_KEY_FROM_KEY _
  | CKM_CONCATENATE_BASE_AND_KEY _
  | CKM_XOR_BASE_AND_DATA _
  | CKM_PKCS5_PBKD2 _
  | CKM_CS_UNKNOWN _ ->
    None

let to_string x = mechanism_type x |> P11_mechanism_type.to_string

let pp fmt m = Format.fprintf fmt "%s" @@ to_string m
