(** Generator of C and ML code from [Cstubs] description *)
let stubs_c = "src_driver/pkcs11_stubs.c"
let stubs_ml = "src_driver/pkcs11_generated.ml"

let prefix = "cs_pkcs11_"

let _ =
  Ctypes_helpers.with_out_fmt stubs_c begin fun fmt ->
    Format.fprintf fmt "#include <caml/mlvalues.h>\n";
    Format.fprintf fmt "#include \"../include/pkcs11_module.h\"\n";
    Cstubs.write_c fmt ~prefix (module Pkcs11_bindings.C);
  end;

  Ctypes_helpers.with_out_fmt stubs_ml begin fun fmt ->
    Cstubs.write_ml fmt ~prefix (module Pkcs11_bindings.C)
  end
