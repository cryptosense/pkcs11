(** High-level PKCS#11 types. *)

module AES_CBC_ENCRYPT_DATA_params = P11_aes_cbc_encrypt_data_params
module AES_CTR_params = P11_aes_ctr_params
module AES_key_wrap_params = P11_aes_key_wrap_params
module Attribute = P11_attribute
module Attribute_type = P11_attribute_type
module Attribute_types = P11_attribute_types
module Bigint = P11_bigint
module DES_CBC_ENCRYPT_DATA_params = P11_des_cbc_encrypt_data_params
module Data = P11_hex_data
module EC_KDF = P11_ec_kdf
module Flags = P11_flags
module GCM_params = P11_gcm_params
module HW_feature_type = P11_hw_feature_type
module Info = P11_info
module Key_gen_mechanism = P11_key_gen_mechanism
module Key_type = P11_key_type
module Load_mode = P11_load_mode
module Mechanism = P11_mechanism
module Mechanism_info = P11_mechanism_info
module Mechanism_type = P11_mechanism_type
module Object_class = P11_object_class
module Object_handle = P11_object_handle
module PKCS5_PBKD2_DATA_params = P11_pkcs5_pbkd2_data_params

module PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_type =
  P11_pkcs5_pbkd2_pseudo_random_function_type

module PKCS5_PBKDF2_SALT_SOURCE_type = P11_pkcs5_pbkdf2_salt_source_type
module RSA_PKCS_MGF_type = P11_rsa_pkcs_mgf_type
module RSA_PKCS_OAEP_params = P11_rsa_pkcs_oaep_params
module RSA_PKCS_PSS_params = P11_rsa_pkcs_pss_params
module RV = P11_rv
module Session_handle = P11_session_handle
module Session_info = P11_session_info
module Slot = P11_slot
module Slot_id = P11_slot_id
module Slot_info = P11_slot_info
module Template = P11_template
module Token_info = P11_token_info
module User_type = P11_user_type
module Version = P11_version
