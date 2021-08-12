(** Cmdliner support *)

module Arg : sig
  (** Arguments and converters. *)

  val slot_index : int option Cmdliner.Arg.t
  (** [-s], [--slot], [--slot-index]: select a slot based on its index in
  [C_GetSlotList] output. *)

  val slot_id : int option Cmdliner.Arg.t
  (** [--slot-id]: select a slot by its slot ID (in the list that
      [C_GetSlotList] outputs). *)

  val slot_description : string option Cmdliner.Arg.t
  (** [--slot-description]: select a slot based on its description. *)

  val token_label : string option Cmdliner.Arg.t
  (** [--token-label]: select a slot based on the label of associated token. *)

  val dll : string option Cmdliner.Arg.t
  (** [-d], [--dll]: name of a DLL to load. *)

  val pin : string option Cmdliner.Arg.t
  (** [-p], [--pin]: PIN to pass to [C_Login]. *)

  val load_mode : P11.Load_mode.t Cmdliner.Arg.t
  (** How to access the PKCS11 DLL. [--direct]: call the function directly.
  [--indirect]: use [C_GetFunctionList]. [--indirect_or_direct] (the default): try
  to use [C_GetFunctionList], and if it fails, try directly. *)

  val user_type : P11.User_type.t option Cmdliner.Arg.t
  (** [--user-type]: select user type:
  [CKU_USER] (["user"]) or [CKU_SO] (["so"]) *)
end

module Term : sig
  (** Terms. *)

  val slot_index : int option Cmdliner.Term.t
  (** Shortcut for [Cmdliner.Arg.value Arg.slot_index]. *)

  val slot_id : int option Cmdliner.Term.t
  (** Shortcut for [Cmdliner.Arg.value Arg.slot_id]. *)

  val slot_description : string option Cmdliner.Term.t
  (** Shortcut for [Cmdliner.Arg.value Arg.slot_description]. *)

  val token_label : string option Cmdliner.Term.t
  (** Shortcut for [Cmdliner.Arg.value Arg.token_label]. *)

  val slot : P11.Slot.t option Cmdliner.Term.t
  (** Term that combines the above slot-selecting terms: it makes sure that
  at most one is passed and builds a [P11.Slot.t] value out of it. *)

  val pin : string option Cmdliner.Term.t
  (** Shortcut for [Cmdliner.Arg.value Arg.pin]. *)

  val load_mode : P11.Load_mode.t Cmdliner.Term.t
  (** Shortcut for [Cmdliner.Arg.value Arg.load_mode]. *)

  val user_type : P11.User_type.t option Cmdliner.Term.t
  (** Shortcut for [Cmdliner.Arg.value Arg.user_type]. *)
end
