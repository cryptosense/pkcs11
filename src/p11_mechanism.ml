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
[@@deriving eq,ord,show]

let to_json =
  let simple name = `String name in
  let param name param json_of_param = `Assoc [ name, json_of_param param ] in
  let ulong name p = param name p P11_ulong.to_yojson in
  function
    | CKM_SHA_1 ->
        simple "CKM_SHA_1"
    | CKM_SHA224 ->
        simple "CKM_SHA224"
    | CKM_SHA256 ->
        simple "CKM_SHA256"
    | CKM_SHA384 ->
        simple "CKM_SHA384"
    | CKM_SHA512 ->
        simple "CKM_SHA512"
    | CKM_MD5 ->
        simple "CKM_MD5"
    | CKM_RSA_PKCS_KEY_PAIR_GEN ->
        simple "CKM_RSA_PKCS_KEY_PAIR_GEN"
    | CKM_RSA_X9_31_KEY_PAIR_GEN ->
        simple "CKM_RSA_X9_31_KEY_PAIR_GEN"
    | CKM_RSA_PKCS ->
        simple "CKM_RSA_PKCS"
    | CKM_RSA_PKCS_OAEP p ->
        param "CKM_RSA_PKCS_OAEP" p P11_rsa_pkcs_oaep_params.to_yojson
    | CKM_RSA_X_509 ->
        simple "CKM_RSA_X_509"
    | CKM_RSA_PKCS_PSS p ->
        param "CKM_RSA_PKCS_PSS" p P11_rsa_pkcs_pss_params.to_yojson
    | CKM_SHA1_RSA_PKCS ->
        simple "CKM_SHA1_RSA_PKCS"
    | CKM_SHA224_RSA_PKCS ->
        simple "CKM_SHA224_RSA_PKCS"
    | CKM_SHA256_RSA_PKCS ->
        simple "CKM_SHA256_RSA_PKCS"
    | CKM_SHA384_RSA_PKCS ->
        simple "CKM_SHA384_RSA_PKCS"
    | CKM_SHA512_RSA_PKCS ->
        simple "CKM_SHA512_RSA_PKCS"
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
    | CKM_AES_KEY_GEN ->
        simple "CKM_AES_KEY_GEN"
    | CKM_AES_ECB ->
        simple "CKM_AES_ECB"
    | CKM_AES_CBC p ->
        param "CKM_AES_CBC" p P11_hex_data.to_yojson
    | CKM_AES_CBC_PAD p ->
        param "CKM_AES_CBC_PAD" p P11_hex_data.to_yojson
    | CKM_AES_MAC ->
        simple "CKM_AES_MAC"
    | CKM_AES_MAC_GENERAL p ->
        ulong "CKM_AES_MAC_GENERAL" p
    | CKM_AES_ECB_ENCRYPT_DATA p ->
        param "CKM_AES_ECB_ENCRYPT_DATA" p P11_hex_data.to_yojson
    | CKM_AES_CBC_ENCRYPT_DATA p ->
        param "CKM_AES_CBC_ENCRYPT_DATA" p P11_aes_cbc_encrypt_data_params.to_yojson
    | CKM_DES_KEY_GEN ->
        simple "CKM_DES_KEY_GEN"
    | CKM_DES_ECB ->
        simple "CKM_DES_ECB"
    | CKM_DES_CBC p ->
        param "CKM_DES_CBC" p P11_hex_data.to_yojson
    | CKM_DES_CBC_PAD p ->
        param "CKM_DES_CBC_PAD" p P11_hex_data.to_yojson
    | CKM_DES_MAC ->
        simple "CKM_DES_MAC"
    | CKM_DES_MAC_GENERAL p ->
        ulong "CKM_DES_MAC_GENERAL" p
    | CKM_DES_ECB_ENCRYPT_DATA p ->
        param "CKM_DES_ECB_ENCRYPT_DATA" p P11_hex_data.to_yojson
    | CKM_DES_CBC_ENCRYPT_DATA p ->
        param "CKM_DES_CBC_ENCRYPT_DATA" p P11_des_cbc_encrypt_data_params.to_yojson
    | CKM_DES3_KEY_GEN ->
        simple "CKM_DES3_KEY_GEN"
    | CKM_DES3_ECB ->
        simple "CKM_DES3_ECB"
    | CKM_DES3_CBC p ->
        param "CKM_DES3_CBC" p P11_hex_data.to_yojson
    | CKM_DES3_CBC_PAD p ->
        param "CKM_DES3_CBC_PAD" p P11_hex_data.to_yojson
    | CKM_DES3_MAC ->
        simple "CKM_DES3_MAC"
    | CKM_DES3_MAC_GENERAL p ->
        ulong "CKM_DES3_MAC_GENERAL" p
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
    | CKM_EXTRACT_KEY_FROM_KEY p ->
        ulong "CKM_EXTRACT_KEY_FROM_KEY" p
    | CKM_CONCATENATE_BASE_AND_KEY p ->
        param "CKM_CONCATENATE_BASE_AND_KEY" p P11_object_handle.to_yojson
    | CKM_EC_KEY_PAIR_GEN ->
        simple "CKM_EC_KEY_PAIR_GEN"
    | CKM_ECDSA ->
        simple "CKM_ECDSA"
    | CKM_ECDSA_SHA1 ->
        simple "CKM_ECDSA_SHA1"
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
    | CKM_AES_GCM p ->
        param "CKM_AES_GCM" p P11_gcm_params.to_yojson
    | CKM_SHA_1_HMAC -> simple "CKM_SHA_1_HMAC"
    | CKM_SHA224_HMAC -> simple "CKM_SHA224_HMAC"
    | CKM_SHA256_HMAC -> simple "CKM_SHA256_HMAC"
    | CKM_SHA384_HMAC -> simple "CKM_SHA384_HMAC"
    | CKM_SHA512_HMAC -> simple "CKM_SHA512_HMAC"
    | CKM_GENERIC_SECRET_KEY_GEN -> simple "CKM_GENERIC_SECRET_KEY_GEN"
    | CKM_AES_KEY_WRAP p ->
      param "CKM_AES_KEY_WRAP" p P11_aes_key_wrap_params.to_yojson
    | CKM_CS_UNKNOWN p ->
        param "CKM_NOT_IMPLEMENTED" p P11_ulong.to_yojson

let of_yojson json =
  let parse name param =
    let simple ckm =
      if param = `Null then
        Ok ckm
      else
        Error "Mechanism does not expect a parameter"
    in
    let open Ppx_deriving_yojson_runtime in
    let oaep make = P11_rsa_pkcs_oaep_params.of_yojson param >>= fun r -> Ok (make r) in
    let pbkd2 make = P11_pkcs5_pbkd2_data_params.of_yojson param >>= fun r -> Ok (make r) in
    let pss make = P11_rsa_pkcs_pss_params.of_yojson param >>= fun r -> Ok (make r) in
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
      | "CKM_AES_ECB_ENCRYPT_DATA" ->
          data (fun x -> CKM_AES_ECB_ENCRYPT_DATA x)
      | "CKM_AES_CBC_ENCRYPT_DATA" ->
          P11_aes_cbc_encrypt_data_params.of_yojson param >>= fun r -> Ok (CKM_AES_CBC_ENCRYPT_DATA r)
      | "CKM_DES_KEY_GEN" -> simple CKM_DES_KEY_GEN
      | "CKM_DES_ECB" -> simple CKM_DES_ECB
      | "CKM_DES_CBC" -> data (fun x -> CKM_DES_CBC x)
      | "CKM_DES_CBC_PAD" -> data (fun x -> CKM_DES_CBC_PAD x)
      | "CKM_DES_MAC" -> simple CKM_DES_MAC
      | "CKM_DES_MAC_GENERAL" ->
          P11_ulong.of_yojson param >>= fun r -> Ok (CKM_DES_MAC_GENERAL r)
      | "CKM_DES_ECB_ENCRYPT_DATA" ->
          data (fun x -> CKM_DES_ECB_ENCRYPT_DATA x)
      | "CKM_DES_CBC_ENCRYPT_DATA" ->
          P11_des_cbc_encrypt_data_params.of_yojson param >>= fun r -> Ok (CKM_DES_CBC_ENCRYPT_DATA r)
      | "CKM_DES3_KEY_GEN" -> simple CKM_DES3_KEY_GEN
      | "CKM_DES3_ECB" -> simple CKM_DES3_ECB
      | "CKM_DES3_CBC" -> data (fun x -> CKM_DES3_CBC x)
      | "CKM_DES3_CBC_PAD" -> data (fun x -> CKM_DES3_CBC_PAD x)
      | "CKM_DES3_MAC" -> simple CKM_DES3_MAC
      | "CKM_DES3_MAC_GENERAL" ->
          P11_ulong.of_yojson param >>= fun r -> Ok (CKM_DES3_MAC_GENERAL r)
      | "CKM_DES3_ECB_ENCRYPT_DATA" ->
          data (fun x -> CKM_DES3_ECB_ENCRYPT_DATA x)
      | "CKM_DES3_CBC_ENCRYPT_DATA" ->
          P11_des_cbc_encrypt_data_params.of_yojson param >>= fun r -> Ok (CKM_DES3_CBC_ENCRYPT_DATA r)
      | "CKM_CONCATENATE_BASE_AND_DATA" ->
          data (fun x -> CKM_CONCATENATE_BASE_AND_DATA x)
      | "CKM_CONCATENATE_DATA_AND_BASE" ->
          data (fun x -> CKM_CONCATENATE_DATA_AND_BASE x)
      | "CKM_XOR_BASE_AND_DATA" ->
          data (fun x -> CKM_XOR_BASE_AND_DATA x)
      | "CKM_EXTRACT_KEY_FROM_KEY" ->
          P11_ulong.of_yojson param >>= fun r -> Ok (CKM_EXTRACT_KEY_FROM_KEY r)
      | "CKM_CONCATENATE_BASE_AND_KEY" ->
          P11_object_handle.of_yojson param >>= fun r -> Ok (CKM_CONCATENATE_BASE_AND_KEY r)
      | "CKM_EC_KEY_PAIR_GEN" -> simple CKM_EC_KEY_PAIR_GEN
      | "CKM_ECDSA" -> simple CKM_ECDSA
      | "CKM_ECDSA_SHA1" -> simple CKM_ECDSA_SHA1
      | "CKM_ECDH1_DERIVE" ->
        P11_ecdh1_derive_params.of_yojson param >>= fun r -> Ok (CKM_ECDH1_DERIVE r)
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
        P11_ulong.of_yojson param >>= fun params ->
        Ok (CKM_CS_UNKNOWN params)
  in
  match json with
    | `Assoc [ name, param ] ->
        parse name param
    | `String name ->
        parse name `Null
    | _ ->
        Error "Ill-formed mechanism"

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
    | CKM_CS_UNKNOWN mechanism_type ->
      T.CKM_CS_UNKNOWN mechanism_type

(* Kinds are "tags" on mechanisms which describe how they can be
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

(* There are three ways to structure this function: following the
   numbering of mechanisms in the pkcs11 header, following the
   structure of table 34, or grouping the mechanism that are similar
   together.  Since all the solutions have drawbacks, we chose here to
   follow the numbering of values in the header, to make it easier to
   add new values. *)
let kinds m =
  let open P11_mechanism_type in
  match mechanism_type m with
  | CKM_RSA_PKCS_KEY_PAIR_GEN -> [Generate; Asymmetric; RSA]
  | CKM_RSA_PKCS -> [Encrypt; Sign; SignRecover; Wrap; RSA; Asymmetric]
  | CKM_RSA_9796 -> [Sign; SignRecover; RSA; Asymmetric]
  | CKM_RSA_X_509 -> [Encrypt; Sign; SignRecover; Wrap; RSA; Asymmetric]
  | CKM_MD2_RSA_PKCS -> [Sign; Asymmetric; RSA]
  | CKM_MD5_RSA_PKCS -> [Sign; Asymmetric; RSA]
  | CKM_SHA1_RSA_PKCS -> [Sign; Asymmetric; RSA]
  | CKM_RIPEMD128_RSA_PKCS -> [Sign; Asymmetric; RSA]
  | CKM_RIPEMD160_RSA_PKCS -> [Sign; Asymmetric; RSA]
  | CKM_RSA_PKCS_OAEP -> [Encrypt; Wrap; Asymmetric; RSA]
  | CKM_RSA_X9_31_KEY_PAIR_GEN -> [Generate; Asymmetric; RSA]
  | CKM_RSA_X9_31 -> [Sign; Asymmetric; RSA]
  | CKM_SHA1_RSA_X9_31 -> [Sign; Asymmetric; RSA]
  | CKM_RSA_PKCS_PSS -> [Sign; Asymmetric; RSA]
  | CKM_SHA1_RSA_PKCS_PSS -> [Sign; Asymmetric; RSA]
  | CKM_DSA_KEY_PAIR_GEN -> [Generate; Asymmetric]

  | CKM_DSA
  | CKM_DSA_SHA1
  | CKM_DSA_SHA224
  | CKM_DSA_SHA256
  | CKM_DSA_SHA384
  | CKM_DSA_SHA512 -> [Sign; Asymmetric]

  | CKM_DH_PKCS_KEY_PAIR_GEN -> [Generate; Asymmetric]
  | CKM_DH_PKCS_DERIVE -> [Derive]

  | CKM_X9_42_DH_KEY_PAIR_GEN -> [Generate; Asymmetric]
  | CKM_X9_42_DH_DERIVE -> [Derive; Asymmetric]
  | CKM_X9_42_DH_HYBRID_DERIVE -> [Derive; Asymmetric]
  | CKM_X9_42_MQV_DERIVE -> [Derive; Asymmetric]

  | CKM_SHA256_RSA_PKCS
  | CKM_SHA384_RSA_PKCS
  | CKM_SHA512_RSA_PKCS
  | CKM_SHA256_RSA_PKCS_PSS
  | CKM_SHA384_RSA_PKCS_PSS
  | CKM_SHA512_RSA_PKCS_PSS
  | CKM_SHA224_RSA_PKCS
  | CKM_SHA224_RSA_PKCS_PSS -> [Sign; Asymmetric; RSA]

  | CKM_RC2_KEY_GEN -> [Generate; Symmetric]
  | CKM_RC2_ECB -> [Encrypt; Wrap; Symmetric]
  | CKM_RC2_CBC -> [Encrypt; Wrap; Symmetric]
  | CKM_RC2_MAC -> [Sign; Symmetric]
  | CKM_RC2_MAC_GENERAL -> [Sign; Symmetric]
  | CKM_RC2_CBC_PAD -> [Encrypt; Wrap; Symmetric]

  | CKM_RC4_KEY_GEN -> [Generate; Symmetric]
  | CKM_RC4 -> [Encrypt; Symmetric]

  | CKM_DES_KEY_GEN -> [Generate; Symmetric; DES]
  | CKM_DES_ECB -> [Encrypt; Wrap; Symmetric; DES]
  | CKM_DES_CBC -> [Encrypt; Wrap; Symmetric; DES]
  | CKM_DES_MAC -> [Sign; Symmetric; DES]
  | CKM_DES_MAC_GENERAL -> [Sign; Symmetric; DES]
  | CKM_DES_CBC_PAD  -> [Encrypt; Wrap; Symmetric; DES]
  | CKM_DES2_KEY_GEN
  | CKM_DES3_KEY_GEN -> [Generate; Symmetric; DES3]
  | CKM_DES3_ECB
  | CKM_DES3_CBC  -> [Encrypt; Wrap; Symmetric; DES3]
  | CKM_DES3_MAC
  | CKM_DES3_MAC_GENERAL -> [Sign; Symmetric; DES3]
  | CKM_DES3_CBC_PAD -> [Encrypt; Wrap; Symmetric; DES3]

  | CKM_CDMF_KEY_GEN ->  [Generate; Symmetric]
  | CKM_CDMF_ECB
  | CKM_CDMF_CBC -> [Encrypt; Wrap; Symmetric]
  | CKM_CDMF_MAC
  | CKM_CDMF_MAC_GENERAL ->  [Sign; Symmetric]
  | CKM_CDMF_CBC_PAD -> [Encrypt; Wrap; Symmetric]
  | CKM_DES_OFB64
  | CKM_DES_OFB8
  | CKM_DES_CFB64
  | CKM_DES_CFB8  -> []       (* The reference manual does not say anything *)
  | CKM_MD2 -> [Digest]
  | CKM_MD2_HMAC -> [Sign]
  | CKM_MD2_HMAC_GENERAL -> [Sign]
  | CKM_MD5 -> [Digest]
  | CKM_MD5_HMAC -> [Sign]
  | CKM_MD5_HMAC_GENERAL -> [Sign]
  | CKM_SHA_1 -> [Digest]
  | CKM_SHA_1_HMAC  -> [Sign]
  | CKM_SHA_1_HMAC_GENERAL -> [Sign]
  | CKM_RIPEMD128 -> [Digest]
  | CKM_RIPEMD128_HMAC -> [Sign]
  | CKM_RIPEMD128_HMAC_GENERAL -> [Sign]
  | CKM_RIPEMD160 -> [Digest]
  | CKM_RIPEMD160_HMAC -> [Sign]
  | CKM_RIPEMD160_HMAC_GENERAL -> [Sign]
  | CKM_SHA256 -> [Digest]
  | CKM_SHA256_HMAC -> [Sign]
  | CKM_SHA256_HMAC_GENERAL -> [Sign]
  | CKM_SHA224 -> [Digest]
  | CKM_SHA224_HMAC -> [Sign]
  | CKM_SHA224_HMAC_GENERAL -> [Sign]
  | CKM_SHA384 -> [Digest]
  | CKM_SHA384_HMAC  -> [Sign]
  | CKM_SHA384_HMAC_GENERAL -> [Sign]
  | CKM_SHA512 -> [Digest]
  | CKM_SHA512_HMAC -> [Sign]
  | CKM_SHA512_HMAC_GENERAL -> [Sign]

  (* Not in thse standard *)
  | CKM_SECURID_KEY_GEN
  | CKM_SECURID
  | CKM_HOTP_KEY_GEN
  | CKM_HOTP
  | CKM_ACTI
  | CKM_ACTI_KEY_GEN -> []

  | CKM_CAST_KEY_GEN -> [Generate; Symmetric]
  | CKM_CAST_ECB -> [Symmetric; Encrypt; Wrap]
  | CKM_CAST_CBC -> [Symmetric; Encrypt; Wrap]
  | CKM_CAST_MAC -> [Symmetric; Sign]
  | CKM_CAST_MAC_GENERAL -> [Symmetric; Sign]
  | CKM_CAST_CBC_PAD -> [Symmetric; Encrypt; Wrap]
  | CKM_CAST3_KEY_GEN -> [Generate; Symmetric]
  | CKM_CAST3_ECB -> [Symmetric; Encrypt; Wrap]
  | CKM_CAST3_CBC -> [Symmetric; Encrypt; Wrap]
  | CKM_CAST3_MAC -> [Symmetric; Sign]
  | CKM_CAST3_MAC_GENERAL -> [Symmetric; Sign]
  | CKM_CAST3_CBC_PAD -> [Symmetric; Encrypt; Wrap]
  | CKM_CAST128_KEY_GEN -> [Generate; Symmetric]
  | CKM_CAST128_ECB -> [Symmetric; Encrypt; Wrap]
  | CKM_CAST128_CBC -> [Symmetric; Encrypt; Wrap]
  | CKM_CAST128_MAC -> [Symmetric; Sign]
  | CKM_CAST128_MAC_GENERAL -> [Symmetric; Sign]
  | CKM_CAST128_CBC_PAD -> [Symmetric; Encrypt; Wrap]

  | CKM_RC5_KEY_GEN -> [Generate; Symmetric]
  | CKM_RC5_ECB -> [Symmetric; Encrypt; Wrap]
  | CKM_RC5_CBC -> [Symmetric; Encrypt; Wrap]
  | CKM_RC5_MAC -> [Symmetric; Sign]
  | CKM_RC5_MAC_GENERAL -> [Symmetric; Sign]
  | CKM_RC5_CBC_PAD -> [Symmetric; Encrypt; Wrap]

  | CKM_IDEA_KEY_GEN -> [Generate; Symmetric]
  | CKM_IDEA_ECB  -> [Symmetric; Encrypt; Wrap ]
  | CKM_IDEA_CBC  -> [Symmetric; Encrypt; Wrap ]
  | CKM_IDEA_MAC-> [Symmetric; Sign]
  | CKM_IDEA_MAC_GENERAL -> [Symmetric; Sign]
  | CKM_IDEA_CBC_PAD -> [Symmetric; Encrypt; Wrap]

  | CKM_GENERIC_SECRET_KEY_GEN -> [Generate]
  | CKM_CONCATENATE_BASE_AND_KEY -> [Derive; AES; DES; DES3; Symmetric] (* any secret key *)
  | CKM_CONCATENATE_BASE_AND_DATA -> [Derive; AES; DES; DES3; Symmetric] (* any secret key *)
  | CKM_CONCATENATE_DATA_AND_BASE -> [Derive; AES; DES; DES3; Symmetric] (* any secret key *)
  | CKM_XOR_BASE_AND_DATA -> [Derive; AES; DES; DES3; Symmetric] (* any secret key *)
  | CKM_EXTRACT_KEY_FROM_KEY -> [Derive; AES; DES; DES3; Symmetric] (* any secret key *)

  | CKM_SSL3_PRE_MASTER_KEY_GEN -> [Generate; Symmetric]
  | CKM_SSL3_MASTER_KEY_DERIVE -> [Derive]
  | CKM_SSL3_KEY_AND_MAC_DERIVE -> [Derive]
  | CKM_SSL3_MASTER_KEY_DERIVE_DH -> [Derive]
  | CKM_TLS_PRE_MASTER_KEY_GEN -> [Generate]
  | CKM_TLS_MASTER_KEY_DERIVE -> [Derive]
  | CKM_TLS_KEY_AND_MAC_DERIVE -> [Derive]
  | CKM_TLS_MASTER_KEY_DERIVE_DH -> [Derive]
  | CKM_TLS_PRF -> [Derive]
  | CKM_SSL3_MD5_MAC -> [Sign]
  | CKM_SSL3_SHA1_MAC -> [Sign]

  | CKM_MD5_KEY_DERIVATION -> [Derive]
  | CKM_MD2_KEY_DERIVATION -> [Derive]
  | CKM_SHA1_KEY_DERIVATION -> [Derive]
  | CKM_SHA256_KEY_DERIVATION -> [Derive]
  | CKM_SHA384_KEY_DERIVATION -> [Derive]
  | CKM_SHA512_KEY_DERIVATION -> [Derive]
  | CKM_SHA224_KEY_DERIVATION -> [Derive]

  | CKM_PBE_MD2_DES_CBC -> [Generate; Symmetric]
  | CKM_PBE_MD5_DES_CBC -> [Generate; Symmetric]
  | CKM_PBE_MD5_CAST_CBC -> [Generate; Symmetric]
  | CKM_PBE_MD5_CAST3_CBC -> [Generate; Symmetric]
  | CKM_PBE_MD5_CAST128_CBC -> [Generate; Symmetric]
  | CKM_PBE_SHA1_CAST128_CBC -> [Generate; Symmetric]
  | CKM_PBE_SHA1_RC4_128 ->  [Generate; Symmetric]
  | CKM_PBE_SHA1_RC4_40 ->  [Generate; Symmetric]
  | CKM_PBE_SHA1_DES3_EDE_CBC -> [Generate; Symmetric]
  | CKM_PBE_SHA1_DES2_EDE_CBC -> [Generate; Symmetric]
  | CKM_PBE_SHA1_RC2_128_CBC -> [Generate; Symmetric]
  | CKM_PBE_SHA1_RC2_40_CBC -> [Generate; Symmetric]
  | CKM_PKCS5_PBKD2 -> [Generate; Symmetric]
  | CKM_PBA_SHA1_WITH_SHA1_HMAC -> [Generate; Symmetric]

  | CKM_WTLS_PRE_MASTER_KEY_GEN -> [Generate; Symmetric]
  | CKM_WTLS_MASTER_KEY_DERIVE -> [Derive]
  | CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC -> [Derive]
  | CKM_WTLS_PRF -> [Derive]
  | CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE -> [Derive]
  | CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE -> [Derive]

  | CKM_KEY_WRAP_LYNKS
  | CKM_KEY_WRAP_SET_OAEP  -> [Wrap]
  | CKM_CMS_SIG -> [Sign; SignRecover]

  (* not in the standard *)
  | CKM_KIP_DERIVE
  | CKM_KIP_WRAP
  | CKM_KIP_MAC
  | CKM_CAMELLIA_KEY_GEN
  | CKM_CAMELLIA_ECB
  | CKM_CAMELLIA_CBC
  | CKM_CAMELLIA_MAC
  | CKM_CAMELLIA_MAC_GENERAL
  | CKM_CAMELLIA_CBC_PAD
  | CKM_CAMELLIA_ECB_ENCRYPT_DATA
  | CKM_CAMELLIA_CBC_ENCRYPT_DATA
  | CKM_CAMELLIA_CTR
  | CKM_ARIA_KEY_GEN
  | CKM_ARIA_ECB
  | CKM_ARIA_CBC
  | CKM_ARIA_MAC
  | CKM_ARIA_MAC_GENERAL
  | CKM_ARIA_CBC_PAD
  | CKM_ARIA_ECB_ENCRYPT_DATA
  | CKM_ARIA_CBC_ENCRYPT_DATA -> []

  | CKM_SKIPJACK_KEY_GEN -> [Generate; Symmetric]
  | CKM_SKIPJACK_ECB64
  | CKM_SKIPJACK_CBC64
  | CKM_SKIPJACK_OFB64
  | CKM_SKIPJACK_CFB64
  | CKM_SKIPJACK_CFB32
  | CKM_SKIPJACK_CFB16
  | CKM_SKIPJACK_CFB8 -> [Encrypt]
  | CKM_SKIPJACK_WRAP -> [Wrap]

  | CKM_SKIPJACK_PRIVATE_WRAP -> [Wrap]
  | CKM_SKIPJACK_RELAYX -> [Wrap]

  | CKM_KEA_KEY_PAIR_GEN -> [Generate]
  | CKM_KEA_KEY_DERIVE -> [Derive]
  | CKM_FORTEZZA_TIMESTAMP -> [Sign]
  | CKM_BATON_KEY_GEN -> [Generate]

  | CKM_BATON_ECB128
  | CKM_BATON_ECB96
  | CKM_BATON_CBC128
  | CKM_BATON_COUNTER
  | CKM_BATON_SHUFFLE -> [Encrypt]
  | CKM_BATON_WRAP -> [Wrap]

  | CKM_EC_KEY_PAIR_GEN -> [EC; Asymmetric; Generate]
  | CKM_ECDSA -> [EC; Asymmetric; Sign]
  | CKM_ECDSA_SHA1 -> [EC; Asymmetric; Sign]
  | CKM_ECDH1_DERIVE -> [EC; Asymmetric; Derive; DH]
  | CKM_ECDH1_COFACTOR_DERIVE -> [EC; Asymmetric; Derive; DH]
  | CKM_ECMQV_DERIVE -> [EC; Asymmetric; Derive; DH]

  | CKM_JUNIPER_KEY_GEN -> [Generate; Symmetric]
  | CKM_JUNIPER_ECB128 -> [Encrypt]
  | CKM_JUNIPER_CBC128 -> [Encrypt]
  | CKM_JUNIPER_COUNTER -> [Encrypt]
  | CKM_JUNIPER_SHUFFLE -> [Encrypt]
  | CKM_JUNIPER_WRAP -> [Wrap]
  | CKM_FASTHASH -> [Digest]

  | CKM_AES_KEY_GEN
    -> [AES; Generate; Symmetric]

  | CKM_AES_ECB
  | CKM_AES_CBC
    -> [ AES; Symmetric; Encrypt; Wrap ]

  | CKM_AES_MAC
  | CKM_AES_MAC_GENERAL
    -> [ AES; Symmetric; Sign ]

  | CKM_AES_CBC_PAD
    -> [ AES; Symmetric; Encrypt; Wrap ]

  | CKM_AES_CTR
  | CKM_AES_GCM
    -> [ AES; Symmetric; Encrypt; Wrap ]

  | CKM_BLOWFISH_KEY_GEN
  | CKM_BLOWFISH_CBC
  | CKM_TWOFISH_KEY_GEN
  | CKM_TWOFISH_CBC -> []

  | CKM_DES_ECB_ENCRYPT_DATA
  | CKM_DES_CBC_ENCRYPT_DATA -> [DES; Symmetric; Derive]
  | CKM_DES3_ECB_ENCRYPT_DATA
  | CKM_DES3_CBC_ENCRYPT_DATA -> [DES3; Symmetric; Derive]
  | CKM_AES_ECB_ENCRYPT_DATA
  | CKM_AES_CBC_ENCRYPT_DATA -> [AES; Symmetric; Derive]
  | CKM_DSA_PARAMETER_GEN
  | CKM_DH_PKCS_PARAMETER_GEN
  | CKM_X9_42_DH_PARAMETER_GEN -> [Generate]
  | CKM_AES_KEY_WRAP -> [AES; Wrap]

  | CKM_GOSTR3410_KEY_PAIR_GEN -> [Asymmetric; Generate]
  | CKM_GOSTR3410 -> [Asymmetric; Sign]
  | CKM_GOSTR3410_WITH_GOSTR3411 -> [Asymmetric; Sign]
  | CKM_GOSTR3411 -> [Digest]
  | CKM_GOSTR3411_HMAC -> [Sign]

  | CKM_VENDOR_DEFINED
  | CKM_CS_UNKNOWN _ -> []

(* Return whether [m] has all kinds [k]. *)
let is ks m =
  let kinds = kinds m in
  List.for_all (fun k -> List.mem k kinds) ks

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
  | CKM_AES_KEY_WRAP _
    -> Some P11_key_type.CKK_AES
  | CKM_DES_KEY_GEN
  | CKM_DES_ECB
  | CKM_DES_CBC _
  | CKM_DES_CBC_PAD _
  | CKM_DES_MAC
  | CKM_DES_MAC_GENERAL _
  | CKM_DES_ECB_ENCRYPT_DATA _
  | CKM_DES_CBC_ENCRYPT_DATA _
    -> Some P11_key_type.CKK_DES
  | CKM_DES3_KEY_GEN
  | CKM_DES3_ECB
  | CKM_DES3_CBC _
  | CKM_DES3_CBC_PAD _
  | CKM_DES3_MAC
  | CKM_DES3_MAC_GENERAL _
  | CKM_DES3_ECB_ENCRYPT_DATA _
  | CKM_DES3_CBC_ENCRYPT_DATA _
    -> Some P11_key_type.CKK_DES3
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
  | CKM_SHA512_RSA_PKCS_PSS _
    -> Some P11_key_type.CKK_RSA
  | CKM_RSA_X9_31_KEY_PAIR_GEN
    -> Some P11_key_type.CKK_RSA
  | CKM_EC_KEY_PAIR_GEN
  | CKM_ECDSA
  | CKM_ECDSA_SHA1
  | CKM_ECDH1_DERIVE _
  | CKM_ECDH1_COFACTOR_DERIVE _
  | CKM_ECMQV_DERIVE _
    -> Some P11_key_type.CKK_EC
  | CKM_DSA_KEY_PAIR_GEN
  | CKM_DSA_SHA1
  | CKM_DSA_SHA224
  | CKM_DSA_SHA256
  | CKM_DSA_SHA384
  | CKM_DSA_SHA512
    -> Some P11_key_type.CKK_DSA
  | CKM_SHA_1_HMAC
  | CKM_SHA224_HMAC
  | CKM_SHA256_HMAC
  | CKM_SHA384_HMAC
  | CKM_SHA512_HMAC
  | CKM_GENERIC_SECRET_KEY_GEN
    -> Some P11_key_type.CKK_GENERIC_SECRET
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
