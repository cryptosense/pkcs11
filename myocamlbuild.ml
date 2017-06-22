open Ocamlbuild_plugin

let ctypes_generator name base : unit =
  rule ("ctypes generator: " ^ name)
    ~dep:"%(name)_generator.native"
    ~prods:[ base ^ "_generated.ml";
             base ^ "_stubs.c";
           ]
    (fun env build ->
       let exe = env "./%(name)_generator.native" in
       let arg = env "%(name)" in
       Cmd (S [P exe; A arg])
    )

let lib ~dir base =
  let use_flag = "use_" ^ base in
  let link_flag = "link_" ^ base in
  let lib_installed = Printf.sprintf "-l%s_stubs" base in
  let lib_build = Printf.sprintf "%s/lib%s_stubs.a" dir base in
  flag ["library"; "link"; "byte"; use_flag] (S ([A "-dllib"; A lib_installed]));
  flag ["library"; "link"; "native"; use_flag] (S ([A "-cclib"; A lib_installed]));
  flag ["link"; "ocaml"; link_flag] (A lib_build);
  dep ["link"; "ocaml"; use_flag] [lib_build]

let add_ocamlfind_header_directory pkg =
  let open Findlib in
  match query pkg with
  | exception Ocamlbuild_pack.Findlib.Findlib_error _ -> ()
  | findlib_pkg ->
    let lib_path = findlib_pkg.location in
    flag ["compile"; "c"] (S [A "-I"; P lib_path])

let after_rules () =
  ctypes_generator "from **/*_generator.ml" "%(name: <**/*> and not <**/*_generator>)";
  add_ocamlfind_header_directory "ctypes";
  pdep ["compile"] "depend" (fun s -> [s]);
  pflag ["compile";"c"] "depend" (fun s -> S [A "-I"; P (Filename.dirname s)]);
  lib ~dir:"src_driver" "pkcs11";
  lib ~dir:"src_rev" "pkcs11_rev";
  flag ["here"] (S ([A "-cclib" ;A "-Lsrc_driver"]));
  ()

let () = dispatch (function
    | After_rules -> after_rules ()
    | _ -> ())
