let exclusive_slot_msg =
  "The options --slot-index, --slot-id, --slot-description and --token-label \
   are mutually exclusive."

module Arg = struct
  let slot_index =
    let open Cmdliner.Arg in
    opt (some int) None
    @@ info ~docv:"INDEX"
         ~doc:("Token slot $(docv). " ^ exclusive_slot_msg)
         ["s"; "slot"; "slot-index"]

  let slot_id =
    let open Cmdliner.Arg in
    opt (some int) None
    @@ info ~docv:"ID"
         ~doc:("Token slot $(docv). " ^ exclusive_slot_msg)
         ["slot-id"]

  let slot_description =
    let open Cmdliner.Arg in
    opt (some string) None
    @@ info ~docv:"DESCRIPTION"
         ~doc:
           ("Token slot $(docv). $(docv) must not exceed 64 characters. "
           ^ exclusive_slot_msg)
         ["slot-description"]

  let token_label =
    let open Cmdliner.Arg in
    opt (some string) None
    @@ info ~docv:"LABEL"
         ~doc:
           ("Token $(docv). $(docv) must not exceed 32 characters. "
           ^ exclusive_slot_msg)
         ["token-label"]

  let dll =
    let open Cmdliner.Arg in
    opt (some string) None
    @@ info ~docv:"DLL" ~doc:"PKCS#11 DLL to load." ["d"; "dll"]

  let pin =
    let open Cmdliner.Arg in
    opt (some string) None @@ info ~docv:"PIN" ~doc:"$(docv)" ["p"; "pin"]

  let load_mode =
    let open Cmdliner.Arg in
    let auto =
      info
        ~doc:
          "Try to use C_GetFunctionList, and if it fails, try again without \
           using it."
        ["indirect_or_direct"]
    in
    let ffi = info ~doc:"Do not use C_GetFunctionList." ["direct"] in
    vflag P11.Load_mode.auto
      [(P11.Load_mode.auto, auto); (P11.Load_mode.ffi, ffi)]

  let user_type =
    let open Cmdliner.Arg in
    let converter =
      enum [("user", P11.User_type.CKU_USER); ("so", P11.User_type.CKU_SO)]
    in
    opt (some converter) None
    @@ info ~docv:"USER TYPE"
         ~doc:"Define the $(docv) to use. May be $(i,user) or $(i,so)."
         ["user-type"]
end

module Term = struct
  let slot_index = Cmdliner.Arg.value Arg.slot_index

  let slot_id = Cmdliner.Arg.value Arg.slot_id

  let slot_description = Cmdliner.Arg.value Arg.slot_description

  let token_label = Cmdliner.Arg.value Arg.token_label

  let slot index id descr label =
    let open P11.Slot in
    match (index, id, descr, label) with
    | (None, None, None, None) -> `Ok None
    | (Some i, None, None, None) -> `Ok (Some (Index i))
    | (None, Some i, None, None) -> `Ok (Some (Id i))
    | (None, None, Some s, None) ->
      if String.length s <= 64 then
        `Ok (Some (Description s))
      else
        `Error (true, "DESCRIPTION must not exceed 64 characters")
    | (None, None, None, Some s) ->
      if String.length s <= 32 then
        `Ok (Some (Label s))
      else
        `Error (true, "LABEL must not exceed 32 characters")
    | _ -> `Error (true, exclusive_slot_msg)

  let slot =
    let open Cmdliner.Term in
    ret (const slot $ slot_index $ slot_id $ slot_description $ token_label)

  let pin = Cmdliner.Arg.value Arg.pin

  let load_mode = Cmdliner.Arg.value Arg.load_mode

  let user_type = Cmdliner.Arg.value Arg.user_type
end
