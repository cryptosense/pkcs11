(** Cmdliner support *)

module Arg : sig
  (** Arguments and converters. *)

  (** [-s], [--slot], [--slot-index]: select a slot based on its index in
  [C_GetSlotList] output. *)
  val slot_index : int option Cmdliner.Arg.t

  (** [--slot-id]: select a slot by its slot ID (in the list that
      [C_GetSlotList] outputs). *)
  val slot_id : int option Cmdliner.Arg.t

  (** [--slot-description]: select a slot based on its description. *)
  val slot_description : string option Cmdliner.Arg.t

  (** [--token-label]: select a slot based on the label of associated token. *)
  val token_label : string option Cmdliner.Arg.t

  (** [-d], [--dll]: name of a DLL to load. *)
  val dll : string option Cmdliner.Arg.t

  (** [-p], [--pin]: PIN to pass to [C_Login]. *)
  val pin : string option Cmdliner.Arg.t

  (** How to access the PKCS11 DLL. [--direct]: call the function directly.
  [--indirect]: use [C_GetFunctionList]. [--indirect_or_direct] (the default): try
  to use [C_GetFunctionList], and if it fails, try directly. *)
  val use_get_function_list : [`Auto | `True | `False] Cmdliner.Arg.t

  (** [--user-type]: select user type:
  [CKU_USER] (["user"]) or [CKU_SO] (["so"]) *)
  val user_type : P11.User_type.t option Cmdliner.Arg.t
end

module Term : sig
  (** Terms. *)

  (** Shortcut for [Cmdliner.Arg.value Arg.slot_index]. *)
  val slot_index : int option Cmdliner.Term.t

  (** Shortcut for [Cmdliner.Arg.value Arg.slot_id]. *)
  val slot_id : int option Cmdliner.Term.t

  (** Shortcut for [Cmdliner.Arg.value Arg.slot_description]. *)
  val slot_description : string option Cmdliner.Term.t

  (** Shortcut for [Cmdliner.Arg.value Arg.token_label]. *)
  val token_label : string option Cmdliner.Term.t

  (** Term that combines the above slot-selecting terms: it makes sure that
  at most one is passed and builds a [P11.Slot.t] value out of it. *)
  val slot: P11.Slot.t option Cmdliner.Term.t

  (** Shortcut for [Cmdliner.Arg.value Arg.pin]. *)
  val pin : string option Cmdliner.Term.t

  (** Shortcut for [Cmdliner.Arg.value Arg.use_get_function_list]. *)
  val use_get_function_list : [`Auto | `True | `False] Cmdliner.Term.t

  (** Shortcut for [Cmdliner.Arg.value Arg.user_type]. *)
  val user_type : P11.User_type.t option Cmdliner.Term.t
end
