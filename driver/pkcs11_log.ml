let logging_function = ref ignore

let set_logging_function f = logging_function := f

let log s = !logging_function s
