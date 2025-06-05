# Sigger

Sigger is a CLI based static signature generator and resolver for ELF, PE and MachOs.

## Features

### **addr-to-sig**  
Input a static address from the input binary and almost instantaneously get a signature which will/should stay constant, even if the target binary is updated.

### **sig-to-addr**  
Input any signature, from this tool, IDA sig maker or Sigga (ghidra plugin), and it will return an offset/address corresponding to that signature. You may input wildcards yourself if needed.

## Prequisites

- capstone library  
- a compatible C++17 supported compiler

## How do I install it?

Look it up for your system. It's different for every system.

## Compiling?

```bash
git clone https://github.com/Ragekill3377/Sigger.git && cd Sigger && clang++ -std=c++17 main.cpp -lcapstone -o sig
```

## Usage?

```bash
./sig --help
```

And follow what it says. Simple to use.
