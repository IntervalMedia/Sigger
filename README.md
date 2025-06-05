# Sigger
Sigger is a CLI based static signature generator and resolver for ELF, PE and MachOs.

# Features
**addr-to-sig**
input a static address from the input binary and almost instantaneously get a signature which will/should stay constant, even if the target binary is updated.

**sig-to-addr**
input any signature, from this tool, IDA sig maker or Sigga (ghidra plugin), and it will return an offset/address corresponding to that signature. you may input wildcards yourself if needed.

**prequisites**
-> capstone library

-> a compatible C++17 supported compiler

**How do I install it?**
-> look it up for your system. it's different for every system.

**Compiling?**
-> ``git clone https://github.com/Ragekill3377/Sigger.git && cd Sigger && clang++ -std=c++17 main.cpp -lcapstone -o sig``

**Usage?**
``./sig --help``

-> and follow what it says. simple to use.


