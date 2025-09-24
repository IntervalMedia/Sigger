# Sigger(ios)

Sigger is a CLI based static signature generator and resolver optimised for MachO running on a jailbroken device in Terminal or via ssh

## Features

### **addr-to-sig**  
Input a static address from the input binary and almost instantaneously get a signature which will/should stay constant, even if the target binary is updated.

### **sig-to-addr**  
Input any signature, from this tool, IDA sig maker or Sigga (ghidra plugin), and it will return an offset/address corresponding to that signature. You may input wildcards yourself if needed.

## Prequisites

- capstone library  
- a compatible C++17 supported compiler

## Usage?

```bash
./sig --help
```