(** High-level PKCS#11 interface. *)

module Data = Pkcs11_hex_data
module Session_handle = P11_session_handle
module Object_handle = P11_object_handle
module HW_feature_type = P11_hw_feature_type
module Slot = P11_slot
module Slot_id = P11_slot_id
module Flags = P11_flags
module Object_class = P11_object_class
module Key_type = P11_key_type
module Version = P11_version
module Bigint = Pkcs11_CK_BIGINT
module RV = P11_rv
module Mechanism_type = P11_mechanism_type
module Key_gen_mechanism = P11_key_gen_mechanism
module RSA_PKCS_MGF_type = P11_rsa_pkcs_mgf_type
module RSA_PKCS_OAEP_params = P11_rsa_pkcs_oaep_params
module RSA_PKCS_PSS_params = P11_rsa_pkcs_pss_params
module AES_CBC_ENCRYPT_DATA_params = P11_aes_cbc_encrypt_data_params
module DES_CBC_ENCRYPT_DATA_params = P11_des_cbc_encrypt_data_params
module PKCS5_PBKDF2_SALT_SOURCE_type = P11_pkcs5_pbkdf2_salt_source_type
module PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_type = P11_pkcs5_pbkd2_pseudo_random_function_type
module PKCS5_PBKD2_DATA_params = P11_pkcs5_pbkd2_data_params
module RAW_PAYLOAD_params = P11_raw_payload_params
module Mechanism = P11_mechanism
module User_type = P11_user_type
module Info = P11_info
module Token_info = P11_token_info
module Slot_info = P11_slot_info
module Mechanism_info = P11_mechanism_info
module Session_info = P11_session_info
module Attribute_type = P11_attribute_type
module Attribute_types = P11_attribute_types
module Attribute = P11_attribute
module Template = P11_template

exception CKR of RV.t

module type S =
sig
  val initialize : unit -> unit
  val finalize : unit -> unit
  val get_info : unit -> Info.t
  val get_slot: Slot.t -> (Slot_id.t, string) result
  val get_slot_list : bool -> Slot_id.t list
  val get_slot_info : slot: Slot_id.t -> Slot_info.t
  val get_token_info : slot: Slot_id.t -> Token_info.t
  val get_mechanism_list : slot: Slot_id.t -> Mechanism_type.t list
  val get_mechanism_info :
    slot: Slot_id.t -> Mechanism_type.t -> Mechanism_info.t
  val init_token : slot: Slot_id.t -> pin: string -> label: string -> unit
  val init_PIN : Session_handle.t -> pin: string -> unit
  val set_PIN : Session_handle.t -> oldpin: string -> newpin: string -> unit
  val open_session : slot: Slot_id.t -> flags: Flags.t -> Session_handle.t
  val close_session : Session_handle.t -> unit
  val close_all_sessions : slot: Slot_id.t -> unit
  val get_session_info : Session_handle.t -> Session_info.t
  val login : Session_handle.t -> User_type.t -> string -> unit
  val logout : Session_handle.t -> unit
  val create_object : Session_handle.t -> Template.t -> Object_handle.t
  val copy_object :
    Session_handle.t -> Object_handle.t -> Template.t -> Object_handle.t
  val destroy_object : Session_handle.t -> Object_handle.t -> unit

  (** May request several attributes at the same time. *)
  val get_attribute_value :
    Session_handle.t -> Object_handle.t -> Attribute_types.t -> Template.t

  (** Will request attributes one by one. *)
  val get_attribute_value' :
    Session_handle.t -> Object_handle.t -> Attribute_types.t -> Template.t

  (** Will request several attributes at the same time. (optimized version) *)
  (* https://blogs.janestreet.com/making-staging-explicit/ *)
  val get_attribute_value_optimized :
    Attribute_types.t ->
    [`Optimized of Session_handle.t -> Object_handle.t -> Template.t]

  val set_attribute_value :
    Session_handle.t -> Object_handle.t -> Template.t -> unit
  val find_objects :
    ?max_size:int -> Session_handle.t -> Template.t -> Object_handle.t list
  val encrypt :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t -> Data.t
  val multipart_encrypt_init :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> unit
  val multipart_encrypt_chunck :
    Session_handle.t -> Data.t -> Data.t
  val multipart_encrypt_final :
    Session_handle.t -> Data.t
  val multipart_encrypt :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t list -> Data.t

  val decrypt :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t -> Data.t
  val multipart_decrypt_init :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> unit
  val multipart_decrypt_chunck :
    Session_handle.t -> Data.t -> Data.t
  val multipart_decrypt_final :
    Session_handle.t -> Data.t
  val multipart_decrypt :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t list -> Data.t

  val sign :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t -> Data.t
  val sign_recover :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t -> Data.t
  val multipart_sign_init :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> unit
  val multipart_sign_chunck : Session_handle.t -> Data.t -> unit
  val multipart_sign_final : Session_handle.t -> Data.t
  val multipart_sign :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t list -> Data.t

  val verify :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> data: Data.t ->
    signature: Data.t -> unit
  val verify_recover :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> signature: Data.t ->
    Data.t
  val multipart_verify_init :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> unit
  val multipart_verify_chunck : Session_handle.t -> Data.t -> unit
  val multipart_verify_final : Session_handle.t -> Data.t -> unit
  val multipart_verify :
    Session_handle.t -> Mechanism.t -> Object_handle.t ->
    Data.t list -> Data.t -> unit

  val generate_key :
    Session_handle.t -> Mechanism.t -> Template.t -> Object_handle.t
  val generate_key_pair :
    Session_handle.t -> Mechanism.t -> Template.t -> Template.t ->
    (Object_handle.t * Object_handle.t)
  val wrap_key :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Object_handle.t ->
    Data.t
  val unwrap_key :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t ->
    Template.t -> Object_handle.t
  val derive_key :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Template.t ->
    Object_handle.t

  module Intermediate_level : Pkcs11.S
  module Low_level : Pkcs11.RAW
end

module Make (X: Pkcs11.RAW): S

(** May raise [Pkcs11.Cannot_load_module].  [on_unknown] will be called with a warning
    message when unsupported codes are encountered. *)
val load_driver:
  ?log_calls:(string * Format.formatter) ->
  ?on_unknown:(string -> unit) ->
  dll: string ->
  use_get_function_list: [ `Auto | `False | `True ] ->
  (module S)
