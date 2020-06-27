echo "Don't forget to update the path to your local winsdk"
./CMakeBuild/avcleaner.bin "$1" --strings=true -- -D "_WIN64" -D "_UNICODE" -D "UNICODE" -D "_WINSOCK_DEPRECATED_NO_WARNINGS"\
     "-I" "/usr/local/Cellar/llvm/9.0.1"#"/usr/lib/clang/8.0.1//include" \
     "-I" "/usr/local/Cellar/llvm/9.0.1"#"/usr/lib/clang/8.0.1/" \
     "-I" "/Users/vladimir/dev/avcleaner/Include/msvc-14.15.26726-include"\
     "-I" "/Users/vladimir/dev/avcleaner/Include/10.0.17134.0/ucrt" \
     "-I" "/Users/vladimir/dev/avcleaner/Include/10.0.17134.0/shared" \
     "-I" "/Users/vladimir/dev/avcleaner/Include/10.0.17134.0/um" \
     "-I" "/Users/vladimir/dev/avcleaner/Include/10.0.17134.0/winrt" \
     "-w" \
     "-fdebug-compilation-dir"\
     "-fno-use-cxa-atexit" "-fms-extensions" "-fms-compatibility" \
     "-fms-compatibility-version=19.15.26726" "-std=c++14" "-fdelayed-template-parsing" "-fobjc-runtime=gcc" "-fcxx-exceptions" "-fexceptions" "-fdiagnostics-show-option" "-fcolor-diagnostics" "-x" "c++" -ferror-limit=1900 -target x86_64-pc-windows-msvc19.15.26726\
       "-fsyntax-only" "-disable-free" "-disable-llvm-verifier" "-discard-value-names"\
       "-dwarf-column-info" "-debugger-tuning=gdb" "-momit-leaf-frame-pointer" "-v"
