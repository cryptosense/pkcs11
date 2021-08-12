type t = char

let of_int = Char.chr

let to_int = Char.code

let typ : t Ctypes.typ =
  let write x = Unsigned.UChar.of_int (to_int x) in
  let read x = of_int (Unsigned.UChar.to_int x) in
  Ctypes.view ~read ~write Ctypes.uchar

let zero = Char.chr 0

let one = Char.chr 1
