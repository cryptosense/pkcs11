let with_open_in filename f =
  let channel = open_in filename in
  f channel;
  close_in channel

let input fmt path =
  with_open_in path @@ fun fd ->
  try
    while true do
      Format.fprintf fmt "%s@." (input_line fd)
    done
  with End_of_file -> ()

let () =
  let module Bindings = Pkcs11_rev_decl.Rev_bindings(Pkcs11.Fake()) in
  let filename_prefix = Sys.argv.(1) in
  let file ext = filename_prefix ^ ext in
  let prefix = "cs_pkcs11_rev" in

  let stubs_c = file "_stubs.c" in
  let stubs_ml = file "_generated.ml" in

  begin
    Ctypes_helpers.with_out_fmt stubs_c (fun fmt ->
        input fmt "src/snippets/prelude.h";
        Cstubs_inverted.write_c fmt ~prefix (module Bindings);
      );

    Ctypes_helpers.with_out_fmt stubs_ml
      (fun fmt ->
         Cstubs_inverted.write_ml fmt ~prefix (module Bindings)
      );
  end
