WIN_INCLUDE="/home/vladimir/dev/anti-av/hkclnr/avcleaner"
CLANG_PATH="/usr/lib/clang/8.0.1/"
clang-query "$1" -- -Xclang -ast-dump -D "_WIN64" -D "_UNICODE" -D "UNICODE" -D "_WINSOCK_DEPRECATED_NO_WARNINGS"  -ferror-limit 500 -target x86_64-pc-windows-msvc19.15.26726\
  "-fsyntax-only" "-disable-free" "-disable-llvm-verifier" "-discard-value-names"\
  "-mrelocation-model" "pic" "-pic-level" "2" "-mthread-model" "posix" "-fmath-errno" \
  "-masm-verbose" "-mconstructor-aliases" "-munwind-tables" "-target-cpu" "x86-64" \
  "-dwarf-column-info" "-debugger-tuning=gdb" "-momit-leaf-frame-pointer" "-v"\
  "-resource-dir" "$CLANG_PATH" \
  "-I" "$CLANG_PATH/include" \
  "-I" "$CLANG_PATH" \
  "-I" "$WIN_INCLUDE/Include/msvc-14.15.26726-include"\
  "-I" "$WIN_INCLUDE/Include/10.0.17134.0/ucrt" \
  "-I" "$WIN_INCLUDE/Include/10.0.17134.0/shared" \
  "-I" "$WIN_INCLUDE/Include/10.0.17134.0/um" \
  "-I" "$WIN_INCLUDE/Include/10.0.17134.0/winrt" \
  "-fdeprecated-macro" \
  "-w" \
  "-fdebug-compilation-dir"\
  "-ferror-limit" "190" "-fmessage-length" "237" "-fno-use-cxa-atexit" "-fms-extensions" "-fms-compatibility" \
  "-fms-compatibility-version=19.15.26726" "-std=c++14" "-fdelayed-template-parsing" "-fobjc-runtime=gcc" "-fcxx-exceptions" "-fexceptions" "-fseh-exceptions" "-fdiagnostics-show-option" "-fcolor-diagnostics" "-x" "c++"

