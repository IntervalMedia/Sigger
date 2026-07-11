/*
Optimized for Jailbroken iOS CLI
- Improved parsing/error handling
- Fixed wildcard handling (0xFF is now treated as literal byte, not wildcard)
- Improved architecture sniffing (basic ELF/Mach-O/PE checks)
- Corrected Capstone mode usage for AArch64
- Cleaner CLI command handling
*/

#include "capstone/capstone.h"

#ifndef CS_ARCH_AARCH64
#define CS_ARCH_AARCH64 CS_ARCH_ARM64
#endif

#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <cstdlib>
#include <utility>
#include <stdexcept>
#include <limits>
#include <algorithm>
#include <sys/stat.h> // iOS-friendly file existence check

class iSig {
private:
    const std::string clr_err = "\033[31m"; // red
    const std::string clr_ok  = "\033[32m"; // green
    const std::string clr_hdr = "\033[34m"; // blue
    const std::string clr_alt = "\033[33m"; // yellow
    const std::string clr_rst = "\033[0m";  // reset

    std::mutex lock;

    [[noreturn]] void fatal(const std::string &msg) {
        throw std::runtime_error(msg);
    }

    static bool ieq(const std::string &a, const std::string &b) {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            if (std::tolower(static_cast<unsigned char>(a[i])) !=
                std::tolower(static_cast<unsigned char>(b[i]))) {
                return false;
            }
        }
        return true;
    }

    // Parse unsigned integer from string with base and bounds checks.
    static size_t parse_size_t_or_die(const std::string &s, int base, const char *what) {
        try {
            size_t idx = 0;
            unsigned long long v = std::stoull(s, &idx, base);
            if (idx != s.size()) throw std::invalid_argument("trailing chars");
            if (v > static_cast<unsigned long long>(std::numeric_limits<size_t>::max()))
                throw std::out_of_range("size_t overflow");
            return static_cast<size_t>(v);
        } catch (...) {
            throw std::runtime_error(std::string("invalid ") + what + ": " + s);
        }
    }

    std::vector<uint8_t> bin_load(const std::string &path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) fatal("can't open file (check path/permissions)");
        return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    }

    bool fileExists(const std::string &path) {
        struct stat buffer {};
        return (stat(path.c_str(), &buffer) == 0);
    }

    std::string bin_hex(const std::vector<uint8_t> &buf) {
        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < buf.size(); ++i) {
            ss << std::setw(2) << static_cast<unsigned>(buf[i]);
            if (i + 1 != buf.size()) ss << ' ';
        }
        return ss.str();
    }

    // Wildcards: only "?" or "??"
    std::vector<uint8_t> sig_parse(const std::string &s) {
        std::istringstream stream(s);
        std::string token;
        std::vector<uint8_t> out;

        while (stream >> token) {
            if (token == "?" || token == "??") {
                out.push_back(0xFF); // wildcard sentinel
                continue;
            }

            // Validate 1-2 hex chars
            if (token.empty() || token.size() > 2) {
                fatal("invalid sig token: " + token);
            }
            for (char c : token) {
                if (!std::isxdigit(static_cast<unsigned char>(c))) {
                    fatal("invalid hex in token: " + token);
                }
            }

            size_t v = parse_size_t_or_die(token, 16, "signature byte");
            if (v > 0xFF) fatal("signature byte out of range: " + token);
            out.push_back(static_cast<uint8_t>(v));
        }

        if (out.empty()) fatal("empty signature");
        return out;
    }

    // Basic format sniffing for ELF / Mach-O / PE
    void gettargetarch(cs_arch &arch, cs_mode &mode, const std::vector<uint8_t> &dat) {
        if (dat.size() < 4) fatal("binary too small");

        // ELF: 0x7F 'E' 'L' 'F'
        if (dat.size() >= 20 &&
            dat[0] == 0x7F && dat[1] == 'E' && dat[2] == 'L' && dat[3] == 'F') {
            uint16_t e_machine = static_cast<uint16_t>(dat[18]) |
                                 (static_cast<uint16_t>(dat[19]) << 8);

            if (e_machine == 0x3E) { // EM_X86_64
                arch = CS_ARCH_X86;
                mode = CS_MODE_64;
                return;
            }
            if (e_machine == 0xB7) { // EM_AARCH64
                arch = CS_ARCH_AARCH64;
                mode = CS_MODE_LITTLE_ENDIAN;
                return;
            }
            fatal("unsupported ELF machine");
        }

        // Mach-O (little endian 32/64)
        auto u32le = [&](size_t off) -> uint32_t {
            if (off + 4 > dat.size()) fatal("truncated header");
            return static_cast<uint32_t>(dat[off]) |
                   (static_cast<uint32_t>(dat[off + 1]) << 8) |
                   (static_cast<uint32_t>(dat[off + 2]) << 16) |
                   (static_cast<uint32_t>(dat[off + 3]) << 24);
        };

        uint32_t magic = u32le(0);
        if (magic == 0xFEEDFACE || magic == 0xFEEDFACF || // MH_MAGIC / MH_MAGIC_64 (LE)
            magic == 0xCEFAEDFE || magic == 0xCFFAEDFE) { // BE variants
            // cputype at offset 4
            uint32_t cputype = u32le(4);
            // CPU_TYPE_X86_64 = 0x01000007, CPU_TYPE_ARM64 = 0x0100000C
            if (cputype == 0x01000007u || cputype == 7u) {
                arch = CS_ARCH_X86;
                mode = CS_MODE_64;
                return;
            }
            if (cputype == 0x0100000Cu || cputype == 12u) {
                arch = CS_ARCH_AARCH64;
                mode = CS_MODE_LITTLE_ENDIAN;
                return;
            }
            fatal("unsupported Mach-O cputype");
        }

        // PE: MZ header, then PE\0\0 signature at e_lfanew, machine at +4
        if (dat.size() >= 0x40 && dat[0] == 'M' && dat[1] == 'Z') {
            uint32_t e_lfanew = u32le(0x3C);
            if (e_lfanew + 6 <= dat.size() &&
                dat[e_lfanew] == 'P' && dat[e_lfanew + 1] == 'E' &&
                dat[e_lfanew + 2] == 0 && dat[e_lfanew + 3] == 0) {

                uint16_t machine = static_cast<uint16_t>(dat[e_lfanew + 4]) |
                                   (static_cast<uint16_t>(dat[e_lfanew + 5]) << 8);
                if (machine == 0x8664) { // AMD64
                    arch = CS_ARCH_X86;
                    mode = CS_MODE_64;
                    return;
                }
                if (machine == 0xAA64) { // ARM64
                    arch = CS_ARCH_AARCH64;
                    mode = CS_MODE_LITTLE_ENDIAN;
                    return;
                }
                fatal("unsupported PE machine");
            }
        }

        fatal("unknown binary format/arch");
    }

    std::string instructions_to_pattern(cs_arch arch, const cs_insn *ins, size_t cnt) {
        std::ostringstream out;
        out << std::hex << std::setfill('0');

        for (size_t idx = 0; idx < cnt; ++idx) {
            const cs_insn &inst = ins[idx];
            bool wildcard = false;

            if (inst.detail && arch == CS_ARCH_AARCH64) {
                const cs_arm64 &arm = inst.detail->arm64;
                for (uint8_t op_idx = 0; op_idx < arm.op_count; ++op_idx) {
                    const cs_arm64_op &op = arm.operands[op_idx];
                    if (op.type == ARM64_OP_IMM) {
                        wildcard = true;
                        break;
                    }
                    if (op.type == ARM64_OP_MEM && (op.mem.disp != 0
#ifdef ARM64_REG_PC
                        || op.mem.base == ARM64_REG_PC
#endif
                    )) {
                        wildcard = true;
                        break;
                    }
                }
            }

            for (size_t b = 0; b < inst.size; ++b) {
                if (wildcard && arch == CS_ARCH_AARCH64) out << "??";
                else out << std::setw(2) << static_cast<unsigned>(inst.bytes[b]);

                if (!(idx == cnt - 1 && b == inst.size - 1)) out << ' ';
            }
        }
        return out.str();
    }

    std::pair<std::string, std::vector<uint8_t>>
    bin_disasm_pattern(const std::vector<uint8_t> &blob, size_t off, size_t lim) {
        if (off >= blob.size()) fatal("offset out of range");

        cs_arch arc;
        cs_mode mod;
        gettargetarch(arc, mod, blob);

        csh eng = 0;
        if (cs_open(arc, mod, &eng) != CS_ERR_OK) fatal("capstone init failed");
        cs_option(eng, CS_OPT_DETAIL, CS_OPT_ON);

        cs_insn *inst = nullptr;
        const uint8_t *ptr = blob.data() + off;
        size_t len = blob.size() - off;

        size_t cnt = cs_disasm(eng, ptr, len, 0, lim, &inst);
        if (cnt == 0) {
            cs_close(&eng);
            fatal("disassembly failed");
        }

        std::string pattern = instructions_to_pattern(arc, inst, cnt);
        std::vector<uint8_t> raw;
        raw.reserve(cnt * 4); // rough estimate
        for (size_t idx = 0; idx < cnt; ++idx) {
            raw.insert(raw.end(), inst[idx].bytes, inst[idx].bytes + inst[idx].size);
        }

        cs_free(inst, cnt);
        cs_close(&eng);
        return {pattern, raw};
    }

    std::vector<uint8_t> parse_hex_exact(const std::string &s) {
        std::istringstream stream(s);
        std::string token;
        std::vector<uint8_t> out;

        while (stream >> token) {
            if (token.find('?') != std::string::npos) fatal("wildcards not allowed in --hex-to-apple input");
            if (token.empty() || token.size() > 2) fatal("invalid hex token: " + token);

            for (char c : token) {
                if (!std::isxdigit(static_cast<unsigned char>(c))) {
                    fatal("invalid hex token: " + token);
                }
            }

            size_t v = parse_size_t_or_die(token, 16, "hex byte");
            if (v > 0xFF) fatal("hex byte out of range: " + token);
            out.push_back(static_cast<uint8_t>(v));
        }

        return out;
    }

    std::string apple_signature_from_hex(const std::string &hex) {
        std::vector<uint8_t> bytes = parse_hex_exact(hex);
        if (bytes.empty()) fatal("hex input required");

        csh eng = 0;
        if (cs_open(CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN, &eng) != CS_ERR_OK) {
            fatal("capstone init failed");
        }
        cs_option(eng, CS_OPT_DETAIL, CS_OPT_ON);

        cs_insn *inst = nullptr;
        size_t cnt = cs_disasm(eng, bytes.data(), bytes.size(), 0, 0, &inst);
        if (cnt == 0) {
            cs_close(&eng);
            fatal("unable to disassemble input");
        }

        std::string pattern = instructions_to_pattern(CS_ARCH_AARCH64, inst, cnt);

        cs_free(inst, cnt);
        cs_close(&eng);
        return pattern;
    }

    bool sig_match(const std::vector<uint8_t> &hay, const std::vector<uint8_t> &pat) {
        if (pat.empty() || hay.size() < pat.size()) return false;

        bool found = false;
        for (size_t i = 0; i + pat.size() <= hay.size(); ++i) {
            bool same = true;
            for (size_t j = 0; j < pat.size(); ++j) {
                if (pat[j] != 0xFF && pat[j] != hay[i + j]) {
                    same = false;
                    break;
                }
            }
            if (same) {
                std::lock_guard<std::mutex> lk(lock);
                std::cout << clr_ok << "[+] match @ 0x" << std::hex << i << clr_rst << '\n';
                found = true;
            }
        }
        return found;
    }

    void helpme() {
        std::cout << clr_hdr << "usage:\n" << clr_rst;
        std::cout << clr_alt << "  ./sig <bin> --addr-to-sig <hex_offset>\n";
        std::cout << "  ./sig <bin> --sig-to-addr " << clr_ok << "AA BB ?? CC" << clr_rst << '\n';
        std::cout << "  ./sig " << clr_ok << "--hex-to-apple" << clr_rst << " " << clr_alt << "AA BB CC" << clr_rst << '\n';
        std::cout << "\nnotes:\n";
        std::cout << "  wildcard tokens are only '?' or '??'\n";
        std::cout << "  literal 'FF' is treated as byte 0xFF\n";
    }

    void cmd_hex_to_apple(int ac, char **av) {
        if (ac < 3) fatal("hex string required");
        std::ostringstream ss;
        for (int i = 2; i < ac; ++i) ss << av[i] << ' ';
        std::string pattern = apple_signature_from_hex(ss.str());
        std::cout << clr_ok << "[apple]" << clr_rst << ' ' << pattern << '\n';
    }

    void cmd_addr_to_sig(const std::vector<uint8_t> &buf, const std::string &ofsHex) {
        size_t ofs = parse_size_t_or_die(ofsHex, 16, "offset");
        auto [pattern, raw] = bin_disasm_pattern(buf, ofs, 5);
        std::cout << clr_hdr << "raw:" << clr_rst << '\n' << bin_hex(raw) << '\n';
        std::cout << clr_ok  << "apple:" << clr_rst << '\n' << pattern << '\n';
    }

    void cmd_sig_to_addr(const std::vector<uint8_t> &buf, int ac, char **av) {
        if (ac < 4) fatal("signature required");
        std::ostringstream ss;
        for (int i = 3; i < ac; ++i) ss << av[i] << ' ';
        auto sig = sig_parse(ss.str());
        if (!sig_match(buf, sig)) {
            std::cout << clr_err << "[-] no matches found" << clr_rst << '\n';
        }
    }

public:
    void run(int ac, char **av) {
        if (ac < 2 || ieq(av[1], "--help") || ieq(av[1], "-h")) {
            helpme();
            return;
        }

        std::string first = av[1];
        if (first == "--hex-to-apple") {
            cmd_hex_to_apple(ac, av);
            return;
        }

        if (!fileExists(first)) fatal("no such file: " + first);
        std::vector<uint8_t> buf = bin_load(first);

        if (ac < 4) fatal("not enough args (expected: <bin> <flag> <value...>)");

        std::string flg = av[2];
        if (flg == "--addr-to-sig") {
            cmd_addr_to_sig(buf, av[3]);
        } else if (flg == "--sig-to-addr") {
            cmd_sig_to_addr(buf, ac, av);
        } else {
            fatal("bad flag: " + flg);
        }
    }
};

int main(int argc, char **argv) {
    try {
        iSig app;
        app.run(argc, argv);
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "\033[31m[ERR] " << e.what() << "\033[0m\n";
        return 1;
    }
}
