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
module Bigint = Pkcs11.CK_BIGINT
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

module Mechanism_info :
sig
  type t = Pkcs11.CK_MECHANISM_INFO.u =
    {
      ulMinKeySize : Unsigned.ULong.t;
      ulMaxKeySize : Unsigned.ULong.t;
      flags : Flags.t;
    }
    [@@deriving yojson]

  val to_string : ?newlines: bool -> ?indent: string -> t -> string
  val to_strings :  t -> string list
  val flags_to_string : Flags.t -> string
  val flags_to_strings : Flags.t -> string list

  (* flags possible to set for mechanism infos, aggregated *)
  val allowed_flags : Flags.t
end

module Session_info :
sig
  type t = Pkcs11.CK_SESSION_INFO.u =
    {
      slotID : Unsigned.ULong.t;
      state : Unsigned.ULong.t;
      flags : Flags.t;
      ulDeviceError : Unsigned.ULong.t;
    }
  [@@deriving yojson]
  val to_string : ?newlines: bool -> ?indent: string -> t -> string
  val to_strings : t -> string list
end

module Attribute_type :
sig
  type not_implemented = Pkcs11.CK_ATTRIBUTE_TYPE.not_implemented = NOT_IMPLEMENTED of string

  type 'a t = 'a Pkcs11.CK_ATTRIBUTE_TYPE.u =
    | CKA_CLASS : Pkcs11.CK_OBJECT_CLASS.u t
    | CKA_TOKEN : bool t
    | CKA_PRIVATE : bool t
    | CKA_LABEL : string t
    | CKA_VALUE : string t
    | CKA_TRUSTED : bool t
    | CKA_CHECK_VALUE : not_implemented t
    | CKA_KEY_TYPE : Pkcs11.CK_KEY_TYPE.u t
    | CKA_SUBJECT : string t
    | CKA_ID : string t
    | CKA_SENSITIVE : bool t
    | CKA_ENCRYPT : bool t
    | CKA_DECRYPT : bool t
    | CKA_WRAP : bool t
    | CKA_UNWRAP : bool t
    | CKA_SIGN : bool t
    | CKA_SIGN_RECOVER : bool t
    | CKA_VERIFY : bool t
    | CKA_VERIFY_RECOVER : bool t
    | CKA_DERIVE : bool t
    | CKA_START_DATE : not_implemented t
    | CKA_END_DATE : not_implemented t
    | CKA_MODULUS : Pkcs11.CK_BIGINT.t t
    | CKA_MODULUS_BITS : Pkcs11.CK_ULONG.t t
    | CKA_PUBLIC_EXPONENT : Pkcs11.CK_BIGINT.t t
    | CKA_PRIVATE_EXPONENT : Pkcs11.CK_BIGINT.t t
    | CKA_PRIME_1 : Pkcs11.CK_BIGINT.t t
    | CKA_PRIME_2 : Pkcs11.CK_BIGINT.t t
    | CKA_EXPONENT_1 : Pkcs11.CK_BIGINT.t t
    | CKA_EXPONENT_2 : Pkcs11.CK_BIGINT.t t
    | CKA_COEFFICIENT : Pkcs11.CK_BIGINT.t t
    | CKA_PRIME : Pkcs11.CK_BIGINT.t t
    | CKA_SUBPRIME : Pkcs11.CK_BIGINT.t t
    | CKA_PRIME_BITS : Pkcs11.CK_ULONG.t t
    | CKA_SUBPRIME_BITS : Pkcs11.CK_ULONG.t t
    | CKA_VALUE_LEN : Pkcs11.CK_ULONG.t t
    | CKA_EXTRACTABLE : bool t
    | CKA_LOCAL : bool t
    | CKA_NEVER_EXTRACTABLE : bool t
    | CKA_ALWAYS_SENSITIVE : bool t
    | CKA_KEY_GEN_MECHANISM : Key_gen_mechanism.t t
    | CKA_MODIFIABLE : bool t
    (* | CKA_ECDSA_PARAMS : string t *)
    | CKA_EC_PARAMS : Key_parsers.Asn1.EC.Params.t t
    | CKA_EC_POINT : Key_parsers.Asn1.EC.point t
    | CKA_ALWAYS_AUTHENTICATE : bool t
    | CKA_WRAP_WITH_TRUSTED : bool t
    | CKA_WRAP_TEMPLATE : not_implemented t
    | CKA_UNWRAP_TEMPLATE : not_implemented t
    | CKA_ALLOWED_MECHANISMS : not_implemented t
    | CKA_CS_UNKNOWN: Unsigned.ULong.t -> not_implemented t

  type pack = Pkcs11.CK_ATTRIBUTE_TYPE.pack = Pack : 'a t -> pack
    [@@deriving yojson]

  val of_string : string -> pack


  val compare: 'a t -> 'b t -> int
  val compare_pack: pack -> pack -> int
  val equal : 'a t -> 'b t -> bool
  val equal_pack: pack -> pack -> bool

  val to_string : 'a t -> string

  val pack_to_json : pack -> Yojson.Safe.json

  val elements: pack list
  val known_attribute_types : string list
end

module Attribute_types :
sig
  type t = Attribute_type.pack list [@@deriving yojson]

  (** Return true if an attribute_type is present in an attribute_type list. *)
  val mem : t -> 'a Attribute_type.t -> bool

  (** Remove the duplicates from a list of attribute types *)
  val remove_duplicates : t -> t

  val compare : t -> t -> int
end


module Attribute :
sig

  type 'a t = 'a Attribute_type.t * 'a
  type pack =
    Pkcs11.CK_ATTRIBUTE.pack = Pack : 'a t -> pack
  [@@deriving eq,ord,show,yojson]

  val to_string : 'a t -> string
  val to_string_pair : 'a t -> string * string

  val to_json : 'a t -> Yojson.Safe.json

  val compare_types: 'a t -> 'b t -> int
  val compare_types_pack: pack -> pack -> int
  val compare: 'a t -> 'b t -> int
  val equal: 'a t -> 'b t -> bool
  val equal_types_pack: pack -> pack -> bool
  val equal_values: 'a Attribute_type.t -> 'a -> 'a -> bool

  type kind =
    | Secret (* Can be used by secret keys. *)
    | Public (* Can be used by public keys. *)
    | Private (* Can be used by private keys. *)
    | RSA (* Can ONLY be used by RSA keys. *)
    | EC (* Can ONLY be used by elliptic curves keys. *)

  (** [kinds] returns a list of list.
     An attribute has kinds [ A; B; C ] if one of the lists returned by [kinds]
     has at least kinds [ A; B; C ]. *)
  val kinds: pack -> kind list list

  (** Return whether [a] has all kinds [k]. *)
  val is : kind list -> pack -> bool

  val equal_kind : kind -> kind -> bool
end

module Template :
sig
  type t = Attribute.pack list
    [@@deriving yojson]

  val to_string : t -> string
  val pp : Format.formatter -> t -> unit

  (** Return the value of the first occurrence of an attribute. *)
  val get : t -> 'a Attribute_type.t -> 'a option
  val get_pack : t -> Attribute_type.pack -> Attribute.pack option

  val mem : Attribute.pack -> t -> bool

  val of_raw : Pkcs11.Template.t -> t

  val normalize: t -> t

  (** Compares two normalized templates.  *)
  val compare : t -> t -> int

  val attribute_types: t -> Attribute_type.pack list

  (** [set_attribute attribute template] replaces the value of
      [attribute] in [template] if it already exists and adds
      [attribute] otherwise. *)
  val set_attribute : Attribute.pack -> t -> t

  (** [remove_attribute attribute template] removes the value
      [attribute] from [template] if present. If the attribute_type of
      [attribute] is present with a different value, does nothing. *)
  val remove_attribute: Attribute.pack -> t -> t

  (** [remove_attribute attribute_type template] removes the attribute
      type [attribute_type] from [template] if present with any
      value. *)
  val remove_attribute_type: Attribute_type.pack -> t -> t

  (** Iterate one of the above operation. Same as List.fold_right*)
  val fold: ('a -> t -> t) -> 'a list -> t -> t

  (** [union template1 template2] concatenates the templates. If an
      attribute is present in both [template1] and [template2], the
      value in [template1] is kept. *)
  val union : t -> t -> t

  (** [only_attribute_types attr_types template] keeps only the
      attributes in [template] that are present in [attr_types]. *)
  val only_attribute_types : Attribute_type.pack list -> t -> t

  (** [except_attribute_types attr_types template] removes all the
      attributes in [template] that are present in [attr_types]. *)
  val except_attribute_types : Attribute_type.pack list -> t -> t

  (** [find_attribute_types l template] look up for the value of each
      attribute type in the list l in [template]. Return [None] if one
      or several attribute types cannot be found in [template]. *)
  val find_attribute_types : Attribute_type.pack list -> t -> t option

  (** [correspond source tested] check if [tested] match
      [source].
      It means that it will return true if All the elements
      in [source] are present in [tested].
  *)
  val correspond : source:t -> tested:t -> bool

  (** [diff source tested] search for all the elements of [source]
      that are not equal to an element of [tested].

      It returns a tuple with the list of elements from source
      which are expected but not found in tested and a list of elements
      which are found but with a different value.
  *)
  val diff : source:t -> tested:t -> Attribute.pack list * Attribute.pack list

  (** [hash template] creates a digest from a template.

      It sorts the elements of the template to be sure to have the
      same digest for two templates that have attributes in different
      orders. *)
  val hash : t -> Digest.t

  (** {2 Accessors }  *)

  val get_class : t -> Pkcs11.CK_OBJECT_CLASS.u option
  val get_key_type : t -> Pkcs11.CK_KEY_TYPE.u option
  val get_label : t -> string option
end

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
