(** High-level PKCS#11 bindings. *)

open P11

exception CKR of RV.t

(** High-level interface for PKCS#11 bindings. Contains all functions in the PKCS#11
    specification as well as helper functions to make working with PKCS#11 easier. All functions
    take core P11* types (rather than CK_* types), and structure allocation and populate is
    handled automatically. *)
module type S = sig
  val initialize : unit -> unit

  val initialize_nss : params:Pkcs11.Nss_initialize_arg.u -> unit

  val finalize : unit -> unit

  val get_info : unit -> Info.t

  val get_slot : Slot.t -> (Slot_id.t, string) result

  val get_slot_list : bool -> Slot_id.t list

  val get_slot_info : slot:Slot_id.t -> Slot_info.t

  val get_token_info : slot:Slot_id.t -> Token_info.t

  val get_mechanism_list : slot:Slot_id.t -> Mechanism_type.t list

  val get_mechanism_info :
    slot:Slot_id.t -> Mechanism_type.t -> Mechanism_info.t

  val init_token : slot:Slot_id.t -> pin:string -> label:string -> unit

  val init_PIN : Session_handle.t -> pin:string -> unit

  val set_PIN : Session_handle.t -> oldpin:string -> newpin:string -> unit

  val open_session : slot:Slot_id.t -> flags:Flags.t -> Session_handle.t

  val close_session : Session_handle.t -> unit

  val close_all_sessions : slot:Slot_id.t -> unit

  val get_session_info : Session_handle.t -> Session_info.t

  val login : Session_handle.t -> User_type.t -> string -> unit

  val logout : Session_handle.t -> unit

  val create_object : Session_handle.t -> Template.t -> Object_handle.t

  val copy_object :
    Session_handle.t -> Object_handle.t -> Template.t -> Object_handle.t

  val destroy_object : Session_handle.t -> Object_handle.t -> unit

  val get_attribute_value :
    Session_handle.t -> Object_handle.t -> Attribute_types.t -> Template.t
  (** May request several attributes at the same time. *)

  val get_attribute_value' :
    Session_handle.t -> Object_handle.t -> Attribute_types.t -> Template.t
  (** Will request attributes one by one. *)

  (* https://blogs.janestreet.com/making-staging-explicit/ *)
  val get_attribute_value_optimized :
       Attribute_types.t
    -> [`Optimized of Session_handle.t -> Object_handle.t -> Template.t]
  (** Will request several attributes at the same time. (optimized version) *)

  val set_attribute_value :
    Session_handle.t -> Object_handle.t -> Template.t -> unit

  val find_objects :
    ?max_size:int -> Session_handle.t -> Template.t -> Object_handle.t list

  val encrypt :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t -> Data.t

  val multipart_encrypt_init :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> unit

  val multipart_encrypt_chunck : Session_handle.t -> Data.t -> Data.t

  val multipart_encrypt_final : Session_handle.t -> Data.t

  val multipart_encrypt :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t list -> Data.t

  val decrypt :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t -> Data.t

  val multipart_decrypt_init :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> unit

  val multipart_decrypt_chunck : Session_handle.t -> Data.t -> Data.t

  val multipart_decrypt_final : Session_handle.t -> Data.t

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
       Session_handle.t
    -> Mechanism.t
    -> Object_handle.t
    -> data:Data.t
    -> signature:Data.t
    -> unit

  val verify_recover :
       Session_handle.t
    -> Mechanism.t
    -> Object_handle.t
    -> signature:Data.t
    -> Data.t

  val multipart_verify_init :
    Session_handle.t -> Mechanism.t -> Object_handle.t -> unit

  val multipart_verify_chunck : Session_handle.t -> Data.t -> unit

  val multipart_verify_final : Session_handle.t -> Data.t -> unit

  val multipart_verify :
       Session_handle.t
    -> Mechanism.t
    -> Object_handle.t
    -> Data.t list
    -> Data.t
    -> unit

  val generate_key :
    Session_handle.t -> Mechanism.t -> Template.t -> Object_handle.t

  val generate_key_pair :
       Session_handle.t
    -> Mechanism.t
    -> Template.t
    -> Template.t
    -> Object_handle.t * Object_handle.t

  val wrap_key :
       Session_handle.t
    -> Mechanism.t
    -> Object_handle.t
    -> Object_handle.t
    -> Data.t

  val unwrap_key :
       Session_handle.t
    -> Mechanism.t
    -> Object_handle.t
    -> Data.t
    -> Template.t
    -> Object_handle.t

  val derive_key :
       Session_handle.t
    -> Mechanism.t
    -> Object_handle.t
    -> Template.t
    -> Object_handle.t

  val digest : Session_handle.t -> Mechanism.t -> Data.t -> Data.t
end

type t = (module S)

val initialize : t -> unit

val initialize_nss : t -> params:Pkcs11.Nss_initialize_arg.u -> unit
(** Perform a c_Initialize call with NSS-style initialization parameters as described
    at https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/PKCS11/Module_Specs *)

val finalize : t -> unit

val get_info : t -> Info.t

val get_slot : t -> Slot.t -> (Slot_id.t, string) result

val get_slot_list : t -> bool -> Slot_id.t list

val get_slot_info : t -> slot:Slot_id.t -> Slot_info.t

val get_token_info : t -> slot:Slot_id.t -> Token_info.t

val get_mechanism_list : t -> slot:Slot_id.t -> Mechanism_type.t list

val get_mechanism_info :
  t -> slot:Slot_id.t -> Mechanism_type.t -> Mechanism_info.t

val init_token : t -> slot:Slot_id.t -> pin:string -> label:string -> unit

val init_PIN : t -> Session_handle.t -> pin:string -> unit

val set_PIN : t -> Session_handle.t -> oldpin:string -> newpin:string -> unit

val open_session : t -> slot:Slot_id.t -> flags:Flags.t -> Session_handle.t

val close_session : t -> Session_handle.t -> unit

val close_all_sessions : t -> slot:Slot_id.t -> unit

val get_session_info : t -> Session_handle.t -> Session_info.t

val login : t -> Session_handle.t -> User_type.t -> string -> unit

val logout : t -> Session_handle.t -> unit

val create_object : t -> Session_handle.t -> Template.t -> Object_handle.t

val copy_object :
  t -> Session_handle.t -> Object_handle.t -> Template.t -> Object_handle.t

val destroy_object : t -> Session_handle.t -> Object_handle.t -> unit

val get_attribute_value :
  t -> Session_handle.t -> Object_handle.t -> Attribute_types.t -> Template.t

val get_attribute_value' :
  t -> Session_handle.t -> Object_handle.t -> Attribute_types.t -> Template.t

val get_attribute_value_optimized :
     t
  -> Attribute_types.t
  -> [`Optimized of Session_handle.t -> Object_handle.t -> Template.t]

val set_attribute_value :
  t -> Session_handle.t -> Object_handle.t -> Template.t -> unit

val find_objects :
  t -> ?max_size:int -> Session_handle.t -> Template.t -> Object_handle.t list

val encrypt :
  t -> Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t -> Data.t

val multipart_encrypt_init :
  t -> Session_handle.t -> Mechanism.t -> Object_handle.t -> unit

val multipart_encrypt_chunck : t -> Session_handle.t -> Data.t -> Data.t

val multipart_encrypt_final : t -> Session_handle.t -> Data.t

val multipart_encrypt :
     t
  -> Session_handle.t
  -> Mechanism.t
  -> Object_handle.t
  -> Data.t list
  -> Data.t

val decrypt :
  t -> Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t -> Data.t

val multipart_decrypt_init :
  t -> Session_handle.t -> Mechanism.t -> Object_handle.t -> unit

val multipart_decrypt_chunck : t -> Session_handle.t -> Data.t -> Data.t

val multipart_decrypt_final : t -> Session_handle.t -> Data.t

val multipart_decrypt :
     t
  -> Session_handle.t
  -> Mechanism.t
  -> Object_handle.t
  -> Data.t list
  -> Data.t

val sign :
  t -> Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t -> Data.t

val sign_recover :
  t -> Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t -> Data.t

val multipart_sign_init :
  t -> Session_handle.t -> Mechanism.t -> Object_handle.t -> unit

val multipart_sign_chunck : t -> Session_handle.t -> Data.t -> unit

val multipart_sign_final : t -> Session_handle.t -> Data.t

val multipart_sign :
     t
  -> Session_handle.t
  -> Mechanism.t
  -> Object_handle.t
  -> Data.t list
  -> Data.t

val verify :
     t
  -> Session_handle.t
  -> Mechanism.t
  -> Object_handle.t
  -> data:Data.t
  -> signature:Data.t
  -> unit

val verify_recover :
     t
  -> Session_handle.t
  -> Mechanism.t
  -> Object_handle.t
  -> signature:Data.t
  -> Data.t

val multipart_verify_init :
  t -> Session_handle.t -> Mechanism.t -> Object_handle.t -> unit

val multipart_verify_chunck : t -> Session_handle.t -> Data.t -> unit

val multipart_verify_final : t -> Session_handle.t -> Data.t -> unit

val multipart_verify :
     t
  -> Session_handle.t
  -> Mechanism.t
  -> Object_handle.t
  -> Data.t list
  -> Data.t
  -> unit

val generate_key :
  t -> Session_handle.t -> Mechanism.t -> Template.t -> Object_handle.t

val generate_key_pair :
     t
  -> Session_handle.t
  -> Mechanism.t
  -> Template.t
  -> Template.t
  -> Object_handle.t * Object_handle.t

val wrap_key :
     t
  -> Session_handle.t
  -> Mechanism.t
  -> Object_handle.t
  -> Object_handle.t
  -> Data.t

val unwrap_key :
     t
  -> Session_handle.t
  -> Mechanism.t
  -> Object_handle.t
  -> Data.t
  -> Template.t
  -> Object_handle.t

val derive_key :
     t
  -> Session_handle.t
  -> Mechanism.t
  -> Object_handle.t
  -> Template.t
  -> Object_handle.t

val digest : t -> Session_handle.t -> Mechanism.t -> Data.t -> Data.t

module Wrap_low_level_bindings (X : Pkcs11.LOW_LEVEL_BINDINGS) : S

val load_driver :
     ?log_calls:string * Format.formatter
  -> ?on_unknown:(string -> unit)
  -> ?load_mode:P11.Load_mode.t
  -> string
  -> t
(** May raise [Pkcs11.Cannot_load_module].  [on_unknown] will be called with a warning
    message when unsupported codes are encountered. *)
