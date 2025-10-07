# Sigger(ios)

Sigger is a CLI based static signature generator and resolver optimised for MachO running on a jailbroken device in Terminal or
via ssh

## Features

### **addr-to-sig**
Input a static address from the input binary and almost instantaneously get a signature which will/should stay constant, even if the target binary is updated.

### **sig-to-addr**
Input any signature, from this tool, IDA sig maker or Sigga (ghidra plugin), and it will return an offset/address corresponding to that signature. You may input wildcards yourself if needed.

## Prequisites

- a compatible C++17 supported compiler
- CMake 3.15+ for building the vendored Capstone static library

The Capstone disassembly engine headers are vendored under `vendor/capstone/include`.
Run the bootstrap script once to fetch and build a matching static library into
`vendor/capstone/lib`:

```bash
./scripts/bootstrap_capstone.sh
```

You can override the Capstone version, download URL, build directory, and other
CMake arguments through the environment variables documented in the script.

## Building

After the static library has been generated, build Sigger with:

```bash
g++ -std=c++17 sigger.cpp -I. -Ivendor/capstone/include \
  -Lvendor/capstone/lib -lcapstone -pthread -o sigger
```

### iOS (jailbroken) packaging

For convenience an iOS focused build helper is provided:

```bash
./scripts/build_ios.sh
```

The script targets arm64 by default and will automatically bootstrap an iOS
compatible `libcapstone.a` into `vendor/capstone/lib/ios-<arch>` when needed.
It expects access to the Apple iOS SDK via `xcrun`, but you can customise the
SDK path, compiler, minimum OS version, and architecture through environment
variables documented in the script.

## Usage?

```bash
./sig --help
```
