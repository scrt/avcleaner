# avcleaner
C/C++ source obfuscator for antivirus bypass

![usage example](https://blog.scrt.ch/wp-content/uploads/2020/06/Screenshot-2020-06-18-at-17.50.54-1.png)

## Build

```
docker build . -t avcleaner
docker run -v ~/dev/scrt/avcleaner:/home/toto -it avcleaner bash #adapt ~/dev/scrt/avcleaner to the path where you cloned avcleaner
sudo pacman -Syu
mkdir CMakeBuild && cd CMakeBuild
cmake ..
make -j 2
./avcleaner.bin --help
```

## Usage

For simple programs, this is as easy as:

```
avcleaner.bin test/strings_simplest.c --strings=true --
```

However, you should know that you're using a compiler frontend, which can only work well if you give it the path to ALL the includes required to build your project. As an example, `test/string_simplest.c` includes headers from the WinSDK, and the script `run_example.sh` shows how to handle such scenarios.

## Common errors

```
CommandLine Error: Option 'non-global-value-max-name-size' registered more than once! LLVM ERROR: inconsistency in registered CommandLine options
```

In case you encounter this error, please use `CMakeLists_archlinux.txt` instead of `CMakeLists.txt` and it shoud go away. 
