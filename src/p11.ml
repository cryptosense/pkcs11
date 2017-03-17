(******************************************************************************)
(*                                    Types                                   *)
(******************************************************************************)

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
module Mechanism_info = P11_mechanism_info
module Session_info = P11_session_info
module Attribute_type = P11_attribute_type
module Attribute_types = P11_attribute_types
module Attribute = P11_attribute

module Template =
struct
  type t = Attribute.pack list

  let to_yojson template :Yojson.Safe.json =
    let attributes = List.map (fun (Attribute.Pack x) -> Attribute.to_json x) template in
    let flatten_attribute = function
      | `Assoc l -> l
      | _ -> assert false (* All attributes are represented using [`Assoc]. *)
    in
    let attributes = List.map flatten_attribute attributes |> List.flatten in
    `Assoc attributes

  let of_yojson json =
    let open Ppx_deriving_yojson_runtime in
    match json with
      | `Assoc assoc ->
          begin
            let attributes = List.map (fun (a, b) -> `Assoc [ a, b ]) assoc in
            map_bind Attribute.pack_of_yojson [] attributes
          end
      | _ -> Error "Ill-formed template"

  let rec get : type a . t -> a Attribute_type.t -> a option = fun template x ->
    match template with
      | [] -> None
      | head :: tail ->
          match head with
            | Attribute.Pack (ty,v) ->
                match Pkcs11.CK_ATTRIBUTE_TYPE.compare' ty x with
                  | Pkcs11.CK_ATTRIBUTE_TYPE.Equal -> Some v
                  | Pkcs11.CK_ATTRIBUTE_TYPE.Not_equal _ -> get tail x

  let get_pack template (Attribute_type.Pack ty) =
    match get template ty with
      | None -> None
      | Some v -> Some (Attribute.Pack (ty,v))

  let of_raw = Pkcs11.Template.view

  (** [normalize t] returns a normal form for the template [t]. That
      is, a template that is sorted. *)
  let normalize (t:t) : t =
    List.sort Attribute.compare_pack t

  (** compares two normalized templates  *)
  let rec compare a b =
    match a,b with
      | [], [] -> 0
      | [], _::_ -> -1
      | _::_, [] -> 1
      | a1::a2, b1::b2 ->
          let cmp = Attribute.compare_pack a1 b1 in
          if cmp = 0
          then compare a2 b2
          else cmp

  (** safe mem on templates. *)
  let mem elem = List.exists (Attribute.equal_pack elem)

  (* Operations  *)
  let fold = List.fold_right

  (* Replace the value of [attribute] in [template] if it already
     exists.  Add [attribute] otherwise. *)
  let set_attribute attribute (template : Attribute.pack list) =
    let exists = ref false in
    let replace_value old_attribute =
      if
        Attribute.compare_types_pack old_attribute attribute = 0
      then
        (exists := true; attribute)
      else
        old_attribute
    in
    let template = List.map replace_value template in
    if !exists then
      template
    else
      attribute :: template

  let remove_attribute attribute template =
    List.filter (fun x -> not (Attribute.equal_pack x attribute)) template

  let remove_attribute_type attribute_type template =
    List.filter (fun x ->
        let x = P11_attribute.type_ x in
        not (Attribute_type.equal_pack x attribute_type)) template

  let attribute_types template =
    List.map Attribute.type_ template

  let union template1 template2 =
    List.fold_left
      (fun template attribute -> set_attribute attribute template)
      template2
      (List.rev template1)

  let only_attribute_types types template =
    List.fold_left (fun template attribute ->
        let type_ = Attribute.type_ attribute in
        if List.exists (Attribute_type.equal_pack type_) types
        then attribute::template
        else template
      ) [] template
    |> List.rev

  let except_attribute_types types template =
    List.fold_left (fun template attribute ->
        let type_ = Attribute.type_ attribute in
        if List.exists (Attribute_type.equal_pack type_) types
        then template
        else attribute:: template
      ) [] template
    |> List.rev

  let find_attribute_types types template =
    let rec aux types result =
      match types with
        | [] -> Some (List.rev result)
        | ty::q ->
            begin match get_pack template ty with
              | None -> None
              | Some a -> aux q (a::result)
            end
    in
    aux types []

  let correspond ~source ~tested =
    (* For all the elements of source, check if an element in tested
       correspond. *)
    List.for_all
      (fun x -> List.exists (Attribute.equal_pack x) tested)
      source

  (** For all the elements of source, check if an element in tested
      correspond. Return a tuple with the list of elements from source
      which are expected but not found in tested and a list of elements
      which are found but with a different value.
  *)
  let diff ~source ~tested =
    let empty = ([], []) in
    List.fold_left (
      fun
        (missing, different)
        (Attribute.Pack (attribute, a_value) as pack) ->
        match get tested attribute with
          | None ->
              let missing = pack :: missing in
              missing, different
          | Some value ->
              let different =
                if a_value = value then
                  different
                else
                  pack :: different
              in
              missing, different
    ) empty source

  let to_string t =
    to_yojson t |> Yojson.Safe.to_string

  let pp fmt t = Format.fprintf fmt "%s" @@ to_string t

  let hash t =
    normalize t |> to_string |> Digest.string

  let get_class t = get t Attribute_type.CKA_CLASS
  let get_key_type t = get t Attribute_type.CKA_KEY_TYPE
  let get_label t = get t Attribute_type.CKA_LABEL
end

(******************************************************************************)
(*                                  Commands                                  *)
(******************************************************************************)

exception CKR of RV.t

let () =
  Printexc.register_printer
    begin function
      | CKR s -> Some (RV.to_string s)
      | _ -> None
    end

module type S =
sig
  val initialize : unit -> unit
  val finalize : unit -> unit
  val get_info : unit -> Info.t
  val get_slot : Slot.t -> (Slot_id.t, string) result
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

module Make (X: Pkcs11.RAW) =
struct

  module Low_level = X
  module Intermediate_level = Pkcs11.Make(X)
  include Intermediate_level

  type 'a t = 'a
  let return x = x
  let (>>=) x f = f x

  let check_ckr rv x =
    let rv = Pkcs11.CK_RV.view rv in
    if RV.equal rv RV.CKR_OK
    then x
    else raise (CKR rv)

  let check_ckr_unit rv =
    let rv = Pkcs11.CK_RV.view rv in
    if not (RV.equal rv RV.CKR_OK)
    then raise (CKR rv)

  let (>>?) rv f =
    let rv = Pkcs11.CK_RV.view rv in
    if RV.equal rv RV.CKR_OK
    then f ()
    else raise (CKR rv)

  let initialize : unit -> unit t = fun () ->
    let rv = c_Initialize () in
    check_ckr_unit rv

  let finalize : unit -> unit t = fun () ->
    let rv = c_Finalize () in
    check_ckr_unit rv

  let get_info : unit -> Info.t t = fun () ->
    let rv,info= c_GetInfo () in
    check_ckr rv info

  let get_slot_list : bool -> Slot_id.t list t = fun token_present ->
    let slot_list = Pkcs11.Slot_list.create () in
    c_GetSlotList token_present slot_list >>? fun () ->
    Pkcs11.Slot_list.allocate slot_list;
    c_GetSlotList token_present slot_list >>? fun () ->
    return (Pkcs11.Slot_list.view slot_list)

  let get_slot_info : slot: Slot_id.t -> Slot_info.t t = fun ~slot ->
    let rv, info = c_GetSlotInfo ~slot in
    check_ckr rv info

  let get_token_info: slot: Slot_id.t -> Token_info.t t = fun ~slot ->
    let rv, info = c_GetTokenInfo ~slot in
    check_ckr rv info

  let findi_option p l =
    let rec go i = function
      | [] -> None
      | x::_ when p i x -> Some x
      | _::xs -> go (i+1) xs
    in
    go 0 l

  let trimmed_eq a b =
    let open Ctypes_helpers in
    trim_and_quote a = trim_and_quote b

  let find_slot slot_desc i slot =
    let open Slot in
    match slot_desc with
    | Id id ->
      Slot_id.equal slot @@ Unsigned.ULong.of_int id
    | Index idx ->
      idx = i
    | Description s ->
      let { Slot_info.slotDescription } = get_slot_info ~slot in
      trimmed_eq slotDescription s
    | Label s ->
      let { Token_info.label } = get_token_info ~slot in
      trimmed_eq label s

  let invalid_slot_msg slot =
    let slot_type, value = Slot.to_string slot in
      Printf.sprintf
        "No %s matches %s."
        slot_type value

  let get_slot slot =
    let open Slot in
    let slot_list = get_slot_list false in
    let predicate = find_slot slot in
    match findi_option predicate slot_list with
    | Some s -> Ok s
    | None -> Error (invalid_slot_msg slot)

  let get_mechanism_list: slot: Slot_id.t -> Mechanism_type.t list t =
    fun ~slot ->
      let l = Pkcs11.Mechanism_list.create () in
      c_GetMechanismList ~slot l >>? fun () ->
      Pkcs11.Mechanism_list.allocate l;
      c_GetMechanismList ~slot l >>? fun () ->
      return (Pkcs11.Mechanism_list.view l)

  let get_mechanism_info : slot: Slot_id.t -> Mechanism_type.t ->
    Mechanism_info.t t =
    fun ~slot mech ->
      let rv,info = c_GetMechanismInfo ~slot (Pkcs11.CK_MECHANISM_TYPE.make mech) in
      check_ckr rv info

  let init_token : slot: Slot_id.t -> pin: string -> label: string -> unit t =
    fun ~slot ~pin ~label ->
      check_ckr_unit (c_InitToken ~slot ~pin ~label)

  let init_PIN : Session_handle.t -> pin: string -> unit t =
    fun hSession ~pin ->
    check_ckr_unit (c_InitPIN hSession pin)

  let set_PIN : Session_handle.t -> oldpin: string -> newpin: string -> unit t =
    fun hSession ~oldpin ~newpin ->
      check_ckr_unit (c_SetPIN hSession ~oldpin ~newpin)

  let open_session: slot: Slot_id.t -> flags: Flags.t -> Session_handle.t t =
    fun ~slot ~flags ->
      let rv, hs = c_OpenSession ~slot ~flags in
      check_ckr rv hs

  let close_session: Session_handle.t -> unit t =
    fun hSession ->
      check_ckr_unit (c_CloseSession hSession)

  let close_all_sessions: slot: Slot_id.t -> unit t=
    fun ~slot ->
      check_ckr_unit (c_CloseAllSessions ~slot)

  let get_session_info : Session_handle.t -> Session_info.t t =
    fun hSession ->
      let rv, info = c_GetSessionInfo hSession in
      check_ckr rv info

  let login : Session_handle.t -> User_type.t -> string -> unit t =
    fun hSession usertype pin ->
      let usertype = Pkcs11.CK_USER_TYPE.make usertype in
      check_ckr_unit (c_Login hSession usertype pin)

  let logout : Session_handle.t -> unit t =
    fun hSession ->
      check_ckr_unit (c_Logout hSession)

  let create_object: Session_handle.t -> Template.t -> Object_handle.t t =
    fun hSession template ->
      let rv, hObj = c_CreateObject hSession (Pkcs11.Template.make template) in
      check_ckr rv hObj

  let copy_object: Session_handle.t -> Object_handle.t -> Template.t ->
    Object_handle.t t =
    fun hSession hObj template ->
      let rv, hObj' =
        c_CopyObject hSession hObj (Pkcs11.Template.make template)
      in
      check_ckr rv hObj'

  let destroy_object: Session_handle.t -> Object_handle.t -> unit t =
    fun hSession hObj ->
    check_ckr_unit (c_DestroyObject hSession hObj)

  let get_attribute_value
        hSession
        (hObject: Object_handle.t)
        (query: Attribute_types.t)
    : Template.t t =
    let query = List.map (fun (Attribute_type.Pack x) ->
        Pkcs11.CK_ATTRIBUTE.create (
          Pkcs11.CK_ATTRIBUTE_TYPE.make x)) query in
    let query: Pkcs11.Template.t = Pkcs11.Template.of_list query in
    c_GetAttributeValue hSession hObject query >>? fun () ->
    Pkcs11.Template.allocate query;
    c_GetAttributeValue hSession hObject query >>? fun () ->
    return (Pkcs11.Template.view query)

  let get_attribute_value' hSession hObject query : Template.t t =
    List.fold_left (fun acc attribute ->
        try
          let attr = get_attribute_value hSession hObject [attribute] in
          attr @ acc
        with CKR _ -> acc
      ) [] query
    |> List.rev
    |> return


    module CKA_map = Map.Make(struct
      type t = Attribute_type.pack
      let compare = Attribute_type.compare_pack
    end)
  let get_attribute_value_optimized tracked_attributes =
    (* TODO: have one score table per device / per slot / per session? *)
    let results: (int * int) CKA_map.t ref = ref CKA_map.empty in
    let count = ref 0 in
    let get_results attribute_type =
      try
        CKA_map.find attribute_type !results
      with Not_found ->
        0,0
    in
    let incr_failures (attribute_type : Attribute_type.pack) =
      let successes,failures = get_results attribute_type in
      results :=
        CKA_map.add attribute_type (successes, failures + 1) !results
    in
    let incr_successes (attribute_type : Attribute_type.pack) =
      let successes,failures = get_results attribute_type in
      results :=
        CKA_map.add attribute_type (1+successes, failures) !results
    in
    let can_group attribute_type =
      (* Group only if the failure rate is less than 1%. *)
      let _, failures = get_results attribute_type in
      failures * 100 / !count < 1
    in
    `Optimized (fun session handle ->
        let rec ask_one_by_one acc attributes =
          match attributes with
            | [] ->
                acc (* Order does not matter. *)
            | head :: tail ->
                try
                  let value = get_attribute_value session handle [ head ] in
                  incr_successes head;
                  ask_one_by_one (value @ acc) tail
                with CKR _ ->
                  incr_failures head;
                  ask_one_by_one acc tail
        in
        incr count;
        let group, singles = List.partition can_group tracked_attributes in
        (* Try to ask attributes which work most of the time all at once.
           If it failed, revert to one-by-one mode. *)
        let group_template =
          try
            let r = get_attribute_value session handle group in
            List.iter incr_successes group;
            r
          with CKR _ ->
            ask_one_by_one [] group
        in
        (* Complete the template with other attributes, the ones which fail
           often and which we always ask one by one. *)
        ask_one_by_one group_template singles)

  let set_attribute_value
      hSession
      (hObject: Object_handle.t)
      (query : Attribute.pack list)
    : unit t =
    let query =
      List.map (fun (Attribute.Pack x) ->
          Pkcs11.CK_ATTRIBUTE.make x) query |> Pkcs11.Template.of_list
    in
    c_SetAttributeValue hSession hObject query >>? fun () ->
    return ()

  (* Do not call c_FindObjectFinal.  *)
  let rec find_all acc hSession ~max_size =
    let rv,l = c_FindObjects hSession ~max_size in
    check_ckr rv l >>= fun l ->
    if l <> []
    then find_all (List.rev_append l acc) hSession ~max_size
    else return @@ List.rev acc

  let find_objects:
    ?max_size:int -> Session_handle.t -> Template.t -> Object_handle.t list t =
    fun ?(max_size=5) hSession template ->
      let template = Pkcs11.Template.make template in
      c_FindObjectsInit hSession template >>? fun () ->
      find_all [] hSession ~max_size >>= fun l ->
      let rv = c_FindObjectsFinal hSession in
      check_ckr_unit rv >>= fun () ->
      return l


  let encrypt hSession mech hObject plain : Data.t =
    let mech = Pkcs11.CK_MECHANISM.make mech in
    c_EncryptInit hSession mech hObject >>? fun () ->
    let plain = Pkcs11.Data.of_string plain in
    let cipher = Pkcs11.Data.create () in
    c_Encrypt hSession ~src:plain ~tgt:cipher >>? fun () ->
    let () = Pkcs11.Data.allocate cipher in
    c_Encrypt hSession ~src:plain ~tgt:cipher >>? fun () ->
    return (Pkcs11.Data.to_string cipher)

  let multipart_encrypt_init : Session_handle.t -> Mechanism.t -> Object_handle.t
    -> unit t =
    fun hSession mech hObject ->
      let mech = Pkcs11.CK_MECHANISM.make mech in
      c_EncryptInit hSession mech hObject >>? return

  let multipart_encrypt_chunck hSession plain : Data.t
    =
    let plain = Pkcs11.Data.of_string plain in
    let cipher = Pkcs11.Data.create () in
    c_EncryptUpdate hSession plain cipher >>? fun () ->
    let () = Pkcs11.Data.allocate cipher in
    c_EncryptUpdate hSession plain cipher >>? fun () ->
    return (Pkcs11.Data.to_string cipher)

  let multipart_encrypt_final : Session_handle.t ->  Data.t =
    fun hSession ->
      let cipher = Pkcs11.Data.create () in
      c_EncryptFinal hSession cipher >>? fun () ->
      let () = Pkcs11.Data.allocate cipher in
      c_EncryptFinal hSession cipher >>? fun () ->
      return (Pkcs11.Data.to_string cipher)

  let multipart_encrypt : Session_handle.t -> Mechanism.t -> Object_handle.t ->
    Data.t list -> Data.t =
    fun hSession mech hKey parts ->
      multipart_encrypt_init hSession mech hKey;
      let cipher =
        List.map
          (fun x -> multipart_encrypt_chunck hSession x)
          parts
        |> String.concat ""
      in
      let lastPart = multipart_encrypt_final hSession in
      cipher^lastPart

  let decrypt hSession mech hObject cipher : Data.t =
    let mech = Pkcs11.CK_MECHANISM.make mech in
    c_DecryptInit hSession mech hObject >>? fun () ->
    let cipher = Pkcs11.Data.of_string cipher in
    let plain = Pkcs11.Data.create () in
    c_Decrypt hSession ~src:cipher ~tgt:plain >>? fun () ->
    let () = Pkcs11.Data.allocate plain in
    c_Decrypt hSession ~src:cipher ~tgt:plain >>? fun () ->
    return (Pkcs11.Data.to_string plain)

  let multipart_decrypt_init : Session_handle.t -> Mechanism.t -> Object_handle.t
    -> unit t =
    fun hSession mech hObject ->
      let mech = Pkcs11.CK_MECHANISM.make mech in
      c_DecryptInit hSession mech hObject >>? return

  let multipart_decrypt_chunck hSession cipher : Data.t
    =
    let cipher = Pkcs11.Data.of_string cipher in
    let plain = Pkcs11.Data.create () in
    c_DecryptUpdate hSession cipher plain >>? fun () ->
    let () = Pkcs11.Data.allocate plain in
    c_DecryptUpdate hSession cipher plain >>? fun () ->
    return (Pkcs11.Data.to_string plain)

  let multipart_decrypt_final : Session_handle.t ->  Data.t =
    fun hSession ->
      let plain = Pkcs11.Data.create () in
      c_DecryptFinal hSession plain >>? fun () ->
      let () = Pkcs11.Data.allocate plain in
      c_DecryptFinal hSession plain >>? fun () ->
      return (Pkcs11.Data.to_string plain)

  let multipart_decrypt : Session_handle.t -> Mechanism.t -> Object_handle.t ->
    Data.t list -> Data.t =
    fun hSession mech hKey parts ->
      multipart_decrypt_init hSession mech hKey;
      let plain =
        List.map
          (fun x -> multipart_decrypt_chunck hSession x)
          parts
        |> String.concat ""
      in
      let lastPart = multipart_decrypt_final hSession in
      plain^lastPart

  let sign : Session_handle.t -> Mechanism.t -> Object_handle.t -> Data.t ->
    Data.t =
    fun hSession mech hKey plain ->
      let mech = Pkcs11.CK_MECHANISM.make mech in
      c_SignInit hSession mech hKey >>? fun () ->
      let plain = Pkcs11.Data.of_string plain in
      let signature = Pkcs11.Data.create () in
      c_Sign hSession ~src:plain ~tgt:signature >>? fun () ->
      let () = Pkcs11.Data.allocate signature in
      c_Sign hSession ~src:plain ~tgt:signature >>? fun () ->
      return (Pkcs11.Data.to_string signature)

  let sign_recover:
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

  let multipart_sign_init : Session_handle.t -> Mechanism.t -> Object_handle.t ->
    unit t =
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

  let multipart_sign : Session_handle.t -> Mechanism.t -> Object_handle.t ->
    Data.t list -> Data.t =
    fun hSession mech hKey parts ->
      multipart_sign_init hSession mech hKey >>= fun () ->
      List.iter (multipart_sign_chunck hSession) parts >>= fun () ->
      multipart_sign_final hSession

  let verify:
    Session_handle.t -> Mechanism.t -> Object_handle.t ->
    data: Data.t -> signature: Data.t -> unit t =
    fun hSession mech hKey ~data ~signature ->
      let mech = Pkcs11.CK_MECHANISM.make mech in
      c_VerifyInit hSession mech hKey >>? fun () ->
      let signed = Pkcs11.Data.of_string data in
      let signature = Pkcs11.Data.of_string signature in
      c_Verify hSession ~signed ~signature >>? fun () ->
      return ()

  let verify_recover:
    Session_handle.t -> Mechanism.t -> Object_handle.t -> signature: string ->
    Data.t =
    fun hSession mech hKey ~signature ->
      let mech = Pkcs11.CK_MECHANISM.make mech in
      c_VerifyRecoverInit hSession mech hKey >>? fun () ->
      let signature = Pkcs11.Data.of_string signature in
      let signed = Pkcs11.Data.create () in
      c_VerifyRecover hSession ~signature ~signed >>? fun () ->
      let () = Pkcs11.Data.allocate signed in
      c_VerifyRecover hSession ~signature ~signed >>? fun () ->
      return (Pkcs11.Data.to_string signed)

  let multipart_verify_init:
    Session_handle.t -> Mechanism.t -> Object_handle.t -> unit t =
    fun hSession mech hKey ->
      let mech = Pkcs11.CK_MECHANISM.make mech in
      c_VerifyInit hSession mech hKey >>? return

  let multipart_verify_chunck: Session_handle.t -> Data.t -> unit
    =
    fun hSession part ->
      let part = Pkcs11.Data.of_string part in
      c_VerifyUpdate hSession part >>? return

  let multipart_verify_final : Session_handle.t -> Data.t -> unit t=
    fun hSession signature ->
      let signature = Pkcs11.Data.of_string signature in
      c_VerifyFinal hSession signature >>? return

  let multipart_verify : Session_handle.t -> Mechanism.t -> Object_handle.t ->
    Data.t list -> Data.t -> unit t =
    fun hSession mech hKey parts signature ->
      multipart_verify_init hSession mech hKey >>= fun () ->
      List.iter (multipart_verify_chunck hSession) parts >>= fun () ->
      multipart_verify_final hSession signature

  let generate_key: Session_handle.t -> Mechanism.t -> Template.t ->
    Object_handle.t t =
    fun hSession mech template ->
      let template = Pkcs11.Template.make template in
      let mech = Pkcs11.CK_MECHANISM.make mech in
      let rv, obj = c_GenerateKey hSession mech template in
      check_ckr rv obj

  (* returns [public,private] *)
  let generate_key_pair:
    Session_handle.t -> Mechanism.t -> Template.t ->Template.t ->
    (Object_handle.t * Object_handle.t) t =
    fun hSession mech public privat  ->
      let public = Pkcs11.Template.make public in
      let privat = Pkcs11.Template.make privat in
      let mech = Pkcs11.CK_MECHANISM.make mech in
      let rv, pub, priv = c_GenerateKeyPair hSession mech ~public ~privat in
      check_ckr rv (pub,priv)

  let wrap_key hSession mech wrapping_key (key: Object_handle.t):
    string t =
    let mech = Pkcs11.CK_MECHANISM.make mech in
    let wrapped_key = Pkcs11.Data.create () in
    c_WrapKey hSession mech ~wrapping_key ~key ~wrapped_key >>? fun () ->
    let () = Pkcs11.Data.allocate wrapped_key in
    c_WrapKey hSession mech ~wrapping_key ~key ~wrapped_key >>? fun () ->
    return (Pkcs11.Data.to_string wrapped_key)

  let unwrap_key :
    Session_handle.t ->
    Mechanism.t ->
    Object_handle.t ->
    string ->
    Template.t ->
    Object_handle.t t =
    fun hSession mech unwrapping_key wrapped_key template ->
      let wrapped_key = Pkcs11.Data.of_string wrapped_key in
      let template = Pkcs11.Template.make template in
      let mech = Pkcs11.CK_MECHANISM.make mech in
      let rv,obj =
        c_UnwrapKey hSession mech ~unwrapping_key ~wrapped_key template
      in
      check_ckr rv obj

  let derive_key :
    Session_handle.t ->
    Mechanism.t ->
    Object_handle.t ->
    Template.t ->
    Object_handle.t t =
    fun hSession mech obj template ->
      let template = Pkcs11.Template.make template in
      let mech = Pkcs11.CK_MECHANISM.make mech in
      let rv,obj' = c_DeriveKey hSession mech obj template in
      check_ckr rv obj'

end

let load_driver ?log_calls ?on_unknown ~dll ~use_get_function_list =
  let module Implem =
    (val (Pkcs11.load_driver ?log_calls ?on_unknown ~dll ~use_get_function_list) : Pkcs11.RAW)
  in
  (module (Make (Implem)): S)
