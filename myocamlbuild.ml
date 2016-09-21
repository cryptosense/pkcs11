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


let after_rules () =
  ctypes_generator "from **/*_generator.ml" "%(name: <**/*> and not <**/*_generator>)";
  let ocaml_ctypes_lib_path = Findlib.((query "ctypes").location) in
  flag ["compile"; "c"] (S [A "-I"; P ocaml_ctypes_lib_path]);
  pdep ["compile"; "c"] "depend" (fun s -> [s]);
  pflag ["compile";"c"] "depend" (fun s -> S [A "-I"; P (Filename.dirname s)]);
  flag ["library"; "link"; "byte"; "use_pkcs11"]
      (S ([A "-dllib"; A "-lpkcs11_stubs"]));
  flag ["library"; "link"; "native"; "use_pkcs11"]
      (S ([A "-cclib"; A "-lpkcs11_stubs"]));
    flag ["link"; "ocaml"; "link_pkcs11"]
      (A "src/libpkcs11_stubs.a");
    dep ["link"; "ocaml"; "use_pkcs11"]
      ["src/libpkcs11_stubs.a"];
  ()

let () = dispatch (function
    | After_rules -> after_rules ()
    | _ -> ())
