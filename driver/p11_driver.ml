open P11

exception CKR of RV.t

let () =
  Printexc.register_printer (function
    | CKR s -> Some (RV.to_string s)
    | _ -> None)

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

  val get_attribute_value_optimized :
       Attribute_types.t
    -> [`Optimized of Session_handle.t -> Object_handle.t -> Template.t]

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

module Wrap_low_level_bindings (X : Pkcs11.LOW_LEVEL_BINDINGS) = struct
  module Intermediate_level = Pkcs11.Wrap_low_level_bindings (X)
  open Intermediate_level

  type 'a t = 'a

  let return x = x

  let ( >>= ) x f = f x

  let check_ckr rv x =
    let rv = Pkcs11.CK_RV.view rv in
    if RV.equal rv RV.CKR_OK then
      x
    else
      raise (CKR rv)

  let check_ckr_unit rv =
    let rv = Pkcs11.CK_RV.view rv in
    if not (RV.equal rv RV.CKR_OK) then raise (CKR rv)

  let ( >>? ) rv f =
    let rv = Pkcs11.CK_RV.view rv in
    if RV.equal rv RV.CKR_OK then
      f ()
    else
      raise (CKR rv)

  let initialize : unit -> unit t =
   fun () ->
    let rv = c_Initialize None in
    check_ckr_unit rv

  let initialize_nss : params:string -> unit t =
   fun ~params ->
    let args = Pkcs11.Nss_initialize_arg.make params in
    let rv = c_Initialize (Some args) in
    check_ckr_unit rv

  let finalize : unit -> unit t =
   fun () ->
    let rv = c_Finalize () in
    check_ckr_unit rv

  let get_info : unit -> Info.t t =
   fun () ->
    let (rv, info) = c_GetInfo () in
    check_ckr rv info

  let get_slot_list : bool -> Slot_id.t list t =
   fun token_present ->
    let slot_list = Pkcs11_slot_list.create () in
    c_GetSlotList token_present slot_list >>? fun () ->
    Pkcs11_slot_list.allocate slot_list;
    c_GetSlotList token_present slot_list >>? fun () ->
    return (Pkcs11_slot_list.view slot_list)

  let get_slot_info : slot:Slot_id.t -> Slot_info.t t =
   fun ~slot ->
    let (rv, info) = c_GetSlotInfo ~slot in
    check_ckr rv info

  let get_token_info : slot:Slot_id.t -> Token_info.t t =
   fun ~slot ->
    let (rv, info) = c_GetTokenInfo ~slot in
    check_ckr rv info

  let findi_option p l =
    let rec go i = function
      | [] -> None
      | x :: _ when p i x -> Some x
      | _ :: xs -> go (i + 1) xs
    in
    go 0 l

  let trimmed_eq a b =
    let open P11_helpers in
    trim_and_quote a = trim_and_quote b

  let find_slot slot_desc i slot =
    let open Slot in
    match slot_desc with
    | Id id -> Slot_id.equal slot @@ Unsigned.ULong.of_int id
    | Index idx -> idx = i
    | Description s ->
      let {Slot_info.slotDescription; _} = get_slot_info ~slot in
      trimmed_eq slotDescription s
    | Label s ->
      let {Token_info.label; _} = get_token_info ~slot in
      trimmed_eq label s

  let invalid_slot_msg slot =
    let (slot_type, value) = Slot.to_string slot in
    Printf.sprintf "No %s matches %s." slot_type value

  let get_slot slot =
    let slot_list = get_slot_list false in
    let predicate = find_slot slot in
    match findi_option predicate slot_list with
    | Some s -> Ok s
    | None -> Error (invalid_slot_msg slot)

  let get_mechanism_list : slot:Slot_id.t -> Mechanism_type.t list t =
   fun ~slot ->
    let l = Pkcs11.Mechanism_list.create () in
    c_GetMechanismList ~slot l >>? fun () ->
    Pkcs11.Mechanism_list.allocate l;
    c_GetMechanismList ~slot l >>? fun () ->
    return (Pkcs11.Mechanism_list.view l)

  let get_mechanism_info :
      slot:Slot_id.t -> Mechanism_type.t -> Mechanism_info.t t =
   fun ~slot mech ->
    let (rv, info) =
      c_GetMechanismInfo ~slot (Pkcs11.CK_MECHANISM_TYPE.make mech)
    in
    check_ckr rv info

  let init_token : slot:Slot_id.t -> pin:string -> label:string -> unit t =
   fun ~slot ~pin ~label -> check_ckr_unit (c_InitToken ~slot ~pin ~label)

  let init_PIN : Session_handle.t -> pin:string -> unit t =
   fun hSession ~pin -> check_ckr_unit (c_InitPIN hSession pin)

  let set_PIN : Session_handle.t -> oldpin:string -> newpin:string -> unit t =
   fun hSession ~oldpin ~newpin ->
    check_ckr_unit (c_SetPIN hSession ~oldpin ~newpin)

  let open_session : slot:Slot_id.t -> flags:Flags.t -> Session_handle.t t =
   fun ~slot ~flags ->
    let (rv, hs) = c_OpenSession ~slot ~flags in
    check_ckr rv hs

  let close_session : Session_handle.t -> unit t =
   fun hSession -> check_ckr_unit (c_CloseSession hSession)

  let close_all_sessions : slot:Slot_id.t -> unit t =
   fun ~slot -> check_ckr_unit (c_CloseAllSessions ~slot)

  let get_session_info : Session_handle.t -> Session_info.t t =
   fun hSession ->
    let (rv, info) = c_GetSessionInfo hSession in
    check_ckr rv info

  let login : Session_handle.t -> User_type.t -> string -> unit t =
   fun hSession usertype pin ->
    let usertype = Pkcs11.CK_USER_TYPE.make usertype in
    check_ckr_unit (c_Login hSession usertype pin)

  let logout : Session_handle.t -> unit t =
   fun hSession -> check_ckr_unit (c_Logout hSession)

  let create_object : Session_handle.t -> Template.t -> Object_handle.t t =
   fun hSession template ->
    let (rv, hObj) = c_CreateObject hSession (Pkcs11.Template.make template) in
    check_ckr rv hObj

  let copy_object :
      Session_handle.t -> Object_handle.t -> Template.t -> Object_handle.t t =
   fun hSession hObj template ->
    let (rv, hObj') =
      c_CopyObject hSession hObj (Pkcs11.Template.make template)
    in
    check_ckr rv hObj'

  let destroy_object : Session_handle.t -> Object_handle.t -> unit t =
   fun hSession hObj -> check_ckr_unit (c_DestroyObject hSession hObj)

  let get_attribute_value
      hSession
      (hObject : Object_handle.t)
      (query : Attribute_types.t) : Template.t t =
    let query =
      List.map
        (fun (Attribute_type.Pack x) ->
          Pkcs11.CK_ATTRIBUTE.create (Pkcs11.CK_ATTRIBUTE_TYPE.make x))
        query
    in
    let query : Pkcs11.Template.t = Pkcs11.Template.of_list query in
    c_GetAttributeValue hSession hObject query >>? fun () ->
    Pkcs11.Template.allocate query;
    c_GetAttributeValue hSession hObject query >>? fun () ->
    return (Pkcs11.Template.view query)

  let get_attribute_value' hSession hObject query : Template.t t =
    List.fold_left
      (fun acc attribute ->
        try
          let attr = get_attribute_value hSession hObject [attribute] in
          attr @ acc
        with
        | CKR _ -> acc)
      [] query
    |> List.rev
    |> return

  module CKA_map = Map.Make (struct
    type t = Attribute_type.pack

    let compare = Attribute_type.compare_pack
  end)

  let get_attribute_value_optimized tracked_attributes =
    (* TODO: have one score table per device / per slot / per session? *)
    let results : (int * int) CKA_map.t ref = ref CKA_map.empty in
    let count = ref 0 in
    let get_results attribute_type =
      try CKA_map.find attribute_type !results with
      | Not_found -> (0, 0)
    in
    let incr_failures (attribute_type : Attribute_type.pack) =
      let (successes, failures) = get_results attribute_type in
      results := CKA_map.add attribute_type (successes, failures + 1) !results
    in
    let incr_successes (attribute_type : Attribute_type.pack) =
      let (successes, failures) = get_results attribute_type in
      results := CKA_map.add attribute_type (1 + successes, failures) !results
    in
    let can_group attribute_type =
      (* Group only if the failure rate is less than 1%. *)
      let (_, failures) = get_results attribute_type in
      failures * 100 / !count < 1
    in
    `Optimized
      (fun session handle ->
        let rec ask_one_by_one acc attributes =
          match attributes with
          | [] -> acc (* Order does not matter. *)
          | head :: tail -> (
            try
              let value = get_attribute_value session handle [head] in
              incr_successes head;
              ask_one_by_one (value @ acc) tail
            with
            | CKR _ ->
              incr_failures head;
              ask_one_by_one acc tail)
        in
        incr count;
        let (group, singles) = List.partition can_group tracked_attributes in
        (* Try to ask attributes which work most of the time all at once.
           If it failed, revert to one-by-one mode. *)
        let group_template =
          try
            let r = get_attribute_value session handle group in
            List.iter incr_successes group;
            r
          with
          | CKR _ -> ask_one_by_one [] group
        in
        (* Complete the template with other attributes, the ones which fail
           often and which we always ask one by one. *)
        ask_one_by_one group_template singles)

  let set_attribute_value
      hSession
      (hObject : Object_handle.t)
      (query : Attribute.pack list) : unit t =
    let query =
      List.map (fun (Attribute.Pack x) -> Pkcs11.CK_ATTRIBUTE.make x) query
      |> Pkcs11.Template.of_list
    in
    c_SetAttributeValue hSession hObject query >>? fun () -> return ()

  (* Do not call c_FindObjectFinal.  *)
  let rec find_all acc hSession ~max_size =
    let (rv, l) = c_FindObjects hSession ~max_size in
    check_ckr rv l >>= fun l ->
    if l <> [] then
      find_all (List.rev_append l acc) hSession ~max_size
    else
      return @@ List.rev acc

  let find_objects :
      ?max_size:int -> Session_handle.t -> Template.t -> Object_handle.t list t
      =
   fun ?(max_size = 5) hSession template ->
    let template = Pkcs11.Template.make template in
    c_FindObjectsInit hSession template >>? fun () ->
    find_all [] hSession ~max_size >>= fun l ->
    let rv = c_FindObjectsFinal hSession in
    check_ckr_unit rv >>= fun () -> return l

  let encrypt hSession mech hObject plain : Data.t =
    let mech = Pkcs11.CK_MECHANISM.make mech in
    c_EncryptInit hSession mech hObject >>? fun () ->
    let plain = Pkcs11.Data.of_string plain in
    let cipher = Pkcs11.Data.create () in
    c_Encrypt hSession ~src:plain ~tgt:cipher >>? fun () ->
    let () = Pkcs11.Data.allocate cipher in
    c_Encrypt hSession ~src:plain ~tgt:cipher >>? fun () ->
    return (Pkcs11.Data.to_string cipher)

  let multipart_encrypt_init :
      Session_handle.t -> Mechanism.t -> Object_handle.t -> unit t =
   fun hSession mech hObject ->
    let mech = Pkcs11.CK_MECHANISM.make mech in
    c_EncryptInit hSession mech hObject >>? return

  let multipart_encrypt_chunck hSession plain : Data.t =
    let plain = Pkcs11.Data.of_string plain in
    let cipher = Pkcs11.Data.create () in
    c_EncryptUpdate hSession plain cipher >>? fun () ->
    let () = Pkcs11.Data.allocate cipher in
    c_EncryptUpdate hSession plain cipher >>? fun () ->
    return (Pkcs11.Data.to_string cipher)

  let multipart_encrypt_final : Session_handle.t -> Data.t =
   fun hSession ->
    let cipher = Pkcs11.Data.create () in
    c_EncryptFinal hSession cipher >>? fun () ->
    let () = Pkcs11.Data.allocate cipher in
    c_EncryptFinal hSession cipher >>? fun () ->
    return (Pkcs11.Data.to_string cipher)

  let multipart_encrypt :
         Session_handle.t
      -> Mechanism.t
      -> Object_handle.t
      -> Data.t list
      -> Data.t =
   fun hSession mech hKey parts ->
    multipart_encrypt_init hSession mech hKey;
    let cipher =
      List.map (fun x -> multipart_encrypt_chunck hSession x) parts
      |> String.concat ""
    in
    let lastPart = multipart_encrypt_final hSession in
    cipher ^ lastPart

  let decrypt hSession mech hObject cipher : Data.t =
    let mech = Pkcs11.CK_MECHANISM.make mech in
    c_DecryptInit hSession mech hObject >>? fun () ->
    let cipher = Pkcs11.Data.of_string cipher in
    let plain = Pkcs11.Data.create () in
    c_Decrypt hSession ~src:cipher ~tgt:plain >>? fun () ->
    let () = Pkcs11.Data.allocate plain in
    c_Decrypt hSession ~src:cipher ~tgt:plain >>? fun () ->
    return (Pkcs11.Data.to_string plain)

  let multipart_decrypt_init :
      Session_handle.t -> Mechanism.t -> Object_handle.t -> unit t =
   fun hSession mech hObject ->
    let mech = Pkcs11.CK_MECHANISM.make mech in
    c_DecryptInit hSession mech hObject >>? return

  let multipart_decrypt_chunck hSession cipher : Data.t =
    let cipher = Pkcs11.Data.of_string cipher in
    let plain = Pkcs11.Data.create () in
    c_DecryptUpdate hSession cipher plain >>? fun () ->
    let () = Pkcs11.Data.allocate plain in
    c_DecryptUpdate hSession cipher plain >>? fun () ->
    return (Pkcs11.Data.to_string plain)

  let multipart_decrypt_final : Session_handle.t -> Data.t =
   fun hSession ->
    let plain = Pkcs11.Data.create () in
    c_DecryptFinal hSession plain >>? fun () ->
    let () = Pkcs11.Data.allocate plain in
    c_DecryptFinal hSession plain >>? fun () ->
    return (Pkcs11.Data.to_string plain)

  let multipart_decrypt :
         Session_handle.t
      -> Mechanism.t
      -> Object_handle.t
      -> Data.t list
      -> Data.t =
   fun hSession mech hKey parts ->
    multipart_decrypt_init hSession mech hKey;
    let plain =
      List.map (fun x -> multipart_decrypt_chunck hSession x) parts
      |> String.concat ""
    in
    let lastPart = multipart_decrypt_final hSession in
    plain ^ lastPart

  let sign :
      Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t -> Data.t =
   fun hSession mech hKey plain ->
    let mech = Pkcs11.CK_MECHANISM.make mech in
    c_SignInit hSession mech hKey >>? fun () ->
    let plain = Pkcs11.Data.of_string plain in
    let signature = Pkcs11.Data.create () in
    c_Sign hSession ~src:plain ~tgt:signature >>? fun () ->
    let () = Pkcs11.Data.allocate signature in
    c_Sign hSession ~src:plain ~tgt:signature >>? fun () ->
    return (Pkcs11.Data.to_string signature)

  let sign_recover :
      Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t -> Data.t =
   fun hSession mech hKey plain ->
    let mech = Pkcs11.CK_MECHANISM.make mech in
    c_SignRecoverInit hSession mech hKey >>? fun () ->
    let plain = Pkcs11.Data.of_string plain in
    let signature = Pkcs11.Data.create () in
    c_SignRecover hSession ~src:plain ~tgt:signature >>? fun () ->
    let () = Pkcs11.Data.allocate signature in
    c_SignRecover hSession ~src:plain ~tgt:signature >>? fun () ->
    return (Pkcs11.Data.to_string signature)

  let multipart_sign_init :
      Session_handle.t -> Mechanism.t -> Object_handle.t -> unit t =
   fun hSession mech hKey ->
    let mech = Pkcs11.CK_MECHANISM.make mech in
    c_SignInit hSession mech hKey >>? return

  let multipart_sign_chunck : Session_handle.t -> Data.t -> unit t =
   fun hSession part ->
    let part = Pkcs11.Data.of_string part in
    c_SignUpdate hSession part >>? return

  let multipart_sign_final : Session_handle.t -> Data.t =
   fun hSession ->
    let signature = Pkcs11.Data.create () in
    c_SignFinal hSession signature >>? fun () ->
    let () = Pkcs11.Data.allocate signature in
    c_SignFinal hSession signature >>? fun () ->
    return (Pkcs11.Data.to_string signature)

  let multipart_sign :
         Session_handle.t
      -> Mechanism.t
      -> Object_handle.t
      -> Data.t list
      -> Data.t =
   fun hSession mech hKey parts ->
    multipart_sign_init hSession mech hKey >>= fun () ->
    List.iter (multipart_sign_chunck hSession) parts >>= fun () ->
    multipart_sign_final hSession

  let verify :
         Session_handle.t
      -> Mechanism.t
      -> Object_handle.t
      -> data:Data.t
      -> signature:Data.t
      -> unit t =
   fun hSession mech hKey ~data ~signature ->
    let mech = Pkcs11.CK_MECHANISM.make mech in
    c_VerifyInit hSession mech hKey >>? fun () ->
    let signed = Pkcs11.Data.of_string data in
    let signature = Pkcs11.Data.of_string signature in
    c_Verify hSession ~signed ~signature >>? fun () -> return ()

  let verify_recover :
         Session_handle.t
      -> Mechanism.t
      -> Object_handle.t
      -> signature:string
      -> Data.t =
   fun hSession mech hKey ~signature ->
    let mech = Pkcs11.CK_MECHANISM.make mech in
    c_VerifyRecoverInit hSession mech hKey >>? fun () ->
    let signature = Pkcs11.Data.of_string signature in
    let signed = Pkcs11.Data.create () in
    c_VerifyRecover hSession ~signature ~signed >>? fun () ->
    let () = Pkcs11.Data.allocate signed in
    c_VerifyRecover hSession ~signature ~signed >>? fun () ->
    return (Pkcs11.Data.to_string signed)

  let multipart_verify_init :
      Session_handle.t -> Mechanism.t -> Object_handle.t -> unit t =
   fun hSession mech hKey ->
    let mech = Pkcs11.CK_MECHANISM.make mech in
    c_VerifyInit hSession mech hKey >>? return

  let multipart_verify_chunck : Session_handle.t -> Data.t -> unit =
   fun hSession part ->
    let part = Pkcs11.Data.of_string part in
    c_VerifyUpdate hSession part >>? return

  let multipart_verify_final : Session_handle.t -> Data.t -> unit t =
   fun hSession signature ->
    let signature = Pkcs11.Data.of_string signature in
    c_VerifyFinal hSession signature >>? return

  let multipart_verify :
         Session_handle.t
      -> Mechanism.t
      -> Object_handle.t
      -> Data.t list
      -> Data.t
      -> unit t =
   fun hSession mech hKey parts signature ->
    multipart_verify_init hSession mech hKey >>= fun () ->
    List.iter (multipart_verify_chunck hSession) parts >>= fun () ->
    multipart_verify_final hSession signature

  let generate_key :
      Session_handle.t -> Mechanism.t -> Template.t -> Object_handle.t t =
   fun hSession mech template ->
    let template = Pkcs11.Template.make template in
    let mech = Pkcs11.CK_MECHANISM.make mech in
    let (rv, obj) = c_GenerateKey hSession mech template in
    check_ckr rv obj

  (* returns [public,private] *)
  let generate_key_pair :
         Session_handle.t
      -> Mechanism.t
      -> Template.t
      -> Template.t
      -> (Object_handle.t * Object_handle.t) t =
   fun hSession mech public privat ->
    let public = Pkcs11.Template.make public in
    let privat = Pkcs11.Template.make privat in
    let mech = Pkcs11.CK_MECHANISM.make mech in
    let (rv, pub, priv) = c_GenerateKeyPair hSession mech ~public ~privat in
    check_ckr rv (pub, priv)

  let wrap_key hSession mech wrapping_key (key : Object_handle.t) : string t =
    let mech = Pkcs11.CK_MECHANISM.make mech in
    let wrapped_key = Pkcs11.Data.create () in
    c_WrapKey hSession mech ~wrapping_key ~key ~wrapped_key >>? fun () ->
    let () = Pkcs11.Data.allocate wrapped_key in
    c_WrapKey hSession mech ~wrapping_key ~key ~wrapped_key >>? fun () ->
    return (Pkcs11.Data.to_string wrapped_key)

  let unwrap_key :
         Session_handle.t
      -> Mechanism.t
      -> Object_handle.t
      -> string
      -> Template.t
      -> Object_handle.t t =
   fun hSession mech unwrapping_key wrapped_key template ->
    let wrapped_key = Pkcs11.Data.of_string wrapped_key in
    let template = Pkcs11.Template.make template in
    let mech = Pkcs11.CK_MECHANISM.make mech in
    let (rv, obj) =
      c_UnwrapKey hSession mech ~unwrapping_key ~wrapped_key template
    in
    check_ckr rv obj

  let derive_key :
         Session_handle.t
      -> Mechanism.t
      -> Object_handle.t
      -> Template.t
      -> Object_handle.t t =
   fun hSession mech obj template ->
    let template = Pkcs11.Template.make template in
    let mech = Pkcs11.CK_MECHANISM.make mech in
    let (rv, obj') = c_DeriveKey hSession mech obj template in
    check_ckr rv obj'

  let digest session mechanism input =
    let low_mechanism = Pkcs11.CK_MECHANISM.make mechanism in
    c_DigestInit session low_mechanism >>? fun () ->
    let low_input = Pkcs11.Data.of_string input in
    let low_output = Pkcs11.Data.create () in
    c_Digest session low_input low_output >>? fun () ->
    let () = Pkcs11.Data.allocate low_output in
    c_Digest session low_input low_output >>? fun () ->
    let output = Pkcs11.Data.to_string low_output in
    return output
end

type t = (module S)

let initialize (module S : S) = S.initialize ()

let initialize_nss (module S : S) = S.initialize_nss

let finalize (module S : S) = S.finalize ()

let get_info (module S : S) = S.get_info ()

let get_slot (module S : S) = S.get_slot

let get_slot_list (module S : S) = S.get_slot_list

let get_slot_info (module S : S) = S.get_slot_info

let get_token_info (module S : S) = S.get_token_info

let get_mechanism_list (module S : S) = S.get_mechanism_list

let get_mechanism_info (module S : S) = S.get_mechanism_info

let init_token (module S : S) = S.init_token

let init_PIN (module S : S) = S.init_PIN

let set_PIN (module S : S) = S.set_PIN

let open_session (module S : S) = S.open_session

let close_session (module S : S) = S.close_session

let close_all_sessions (module S : S) = S.close_all_sessions

let get_session_info (module S : S) = S.get_session_info

let login (module S : S) = S.login

let logout (module S : S) = S.logout

let create_object (module S : S) = S.create_object

let copy_object (module S : S) = S.copy_object

let destroy_object (module S : S) = S.destroy_object

let get_attribute_value (module S : S) = S.get_attribute_value

let get_attribute_value' (module S : S) = S.get_attribute_value'

let get_attribute_value_optimized (module S : S) =
  S.get_attribute_value_optimized

let set_attribute_value (module S : S) = S.set_attribute_value

let find_objects (module S : S) = S.find_objects

let encrypt (module S : S) = S.encrypt

let multipart_encrypt_init (module S : S) = S.multipart_encrypt_init

let multipart_encrypt_chunck (module S : S) = S.multipart_encrypt_chunck

let multipart_encrypt_final (module S : S) = S.multipart_encrypt_final

let multipart_encrypt (module S : S) = S.multipart_encrypt

let decrypt (module S : S) = S.decrypt

let multipart_decrypt_init (module S : S) = S.multipart_decrypt_init

let multipart_decrypt_chunck (module S : S) = S.multipart_decrypt_chunck

let multipart_decrypt_final (module S : S) = S.multipart_decrypt_final

let multipart_decrypt (module S : S) = S.multipart_decrypt

let sign (module S : S) = S.sign

let sign_recover (module S : S) = S.sign_recover

let multipart_sign_init (module S : S) = S.multipart_sign_init

let multipart_sign_chunck (module S : S) = S.multipart_sign_chunck

let multipart_sign_final (module S : S) = S.multipart_sign_final

let multipart_sign (module S : S) = S.multipart_sign

let verify (module S : S) = S.verify

let verify_recover (module S : S) = S.verify_recover

let multipart_verify_init (module S : S) = S.multipart_verify_init

let multipart_verify_chunck (module S : S) = S.multipart_verify_chunck

let multipart_verify_final (module S : S) = S.multipart_verify_final

let multipart_verify (module S : S) = S.multipart_verify

let generate_key (module S : S) = S.generate_key

let generate_key_pair (module S : S) = S.generate_key_pair

let wrap_key (module S : S) = S.wrap_key

let unwrap_key (module S : S) = S.unwrap_key

let derive_key (module S : S) = S.derive_key

let digest (module S : S) = S.digest

let load_driver ?log_calls ?on_unknown ?load_mode dll =
  let module Implem = (val Pkcs11.load_driver ?log_calls ?on_unknown ?load_mode
                             dll : Pkcs11.LOW_LEVEL_BINDINGS)
  in
  (module Wrap_low_level_bindings (Implem) : S)
