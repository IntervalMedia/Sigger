/*
Optimized for Jailbroken iOS CLI
- Removed dependencies incompatible with certain iOS environments
- Added file existence check using `stat`
- Adjusted error handling for better iOS terminal support
*/

#include <capstone/capstone.h>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <iostream>
#include <thread>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <cstdlib>
#include <utility>
#include <sys/stat.h> // For iOS-compatible file existence check

class iSig {
private:
    const std::string clr_err = "\033[31m"; // red
    const std::string clr_ok = "\033[32m"; // green
    const std::string clr_hdr = "\033[34m";
    const std::string clr_alt = "\033[33m";
    const std::string clr_rst = "\033[0m";

    std::mutex lock;

    // Error logging wrapper
    void fatal(const std::string &msg) {
        std::lock_guard<std::mutex> lk(lock);
        std::cerr << clr_err << "[ERR] " << msg << clr_rst << std::endl;
        std::exit(1);
    }

    // Load binary file into memory
    std::vector<uint8_t> bin_load(const std::string &path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) fatal("can't open file, do you even have r/o permissions?");
        return {std::istreambuf_iterator<char>(file), {}};
    }

    // Check if a file exists (iOS-compatible)
    bool fileExists(const std::string &path) {
        struct stat buffer;
        return (stat(path.c_str(), &buffer) == 0);
    }

    // Hex formatter
    std::string bin_hex(const std::vector<uint8_t> &buf) {
        std::stringstream ss;
        for (uint8_t ch : buf)
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ch) << ' ';
        return ss.str();
    }

    // Parse signature string into byte vector
    std::vector<uint8_t> sig_parse(const std::string &s) {
        std::istringstream stream(s);
        std::string token;
        std::vector<uint8_t> out;
        while (stream >> token)
            out.push_back((token == "??" || token == "?" || token == "ff") ? 0xFF : std::stoul(token, nullptr, 16));
        return out;
    }

    // Determine architecture
    void gettargetarch(cs_arch &arch, cs_mode &mode, const std::vector<uint8_t> &dat) {
        uint16_t eid;
        if (dat.size() < 20 || dat[0] != 0x7f || dat[1] != 'E') fatal("bad binary");
        eid = dat[18] | (dat[19] << 8);

        if (eid == 0x3E) { // PE or ELF
            arch = CS_ARCH_X86;
            mode = CS_MODE_64;
        } else if (eid == 0xB7) { // Mach-O
            arch = CS_ARCH_AARCH64;
            mode = CS_MODE_ARM;
        } else {
            fatal("unknown arch");
        }
    }

    // Produce formatted signature tokens for an instruction stream
    std::string instructions_to_pattern(cs_arch arch, const cs_insn *ins, size_t cnt) {
        std::ostringstream out;
        for (size_t idx = 0; idx < cnt; ++idx) {
            const cs_insn &inst = ins[idx];
            bool wildcard = false;

            if (inst.detail) {
                if (arch == CS_ARCH_AARCH64) {
                    const cs_arm64 &arm = inst.detail->arm64;
                    for (uint8_t op_idx = 0; op_idx < arm.op_count; ++op_idx) {
                        const cs_arm64_op &op = arm.operands[op_idx];
                        if (op.type == ARM64_OP_IMM) {
                            wildcard = true;
                            break;
                        }
                        if (op.type == ARM64_OP_MEM && (op.mem.disp != 0 || op.mem.base == ARM64_REG_PC)) {
                            wildcard = true;
                            break;
                        }
                    }
                }
            }

            for (size_t b = 0; b < inst.size; ++b) {
                if (wildcard && arch == CS_ARCH_AARCH64)
                    out << "??";
                else
                    out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(inst.bytes[b]);
                if (!(idx == cnt - 1 && b == inst.size - 1)) out << ' ';
            }
        }
        return out.str();
    }

    // Disassemble binary to Apple signature pattern
    std::pair<std::string, std::vector<uint8_t>> bin_disasm_pattern(const std::vector<uint8_t> &blob, size_t off, size_t lim) {
        cs_arch arc;
        cs_mode mod;
        csh eng;
        cs_insn *inst;
        const uint8_t *ptr;
        size_t len;

        gettargetarch(arc, mod, blob);
        if (cs_open(arc, mod, &eng) != CS_ERR_OK) fatal("capstone fail");
        cs_option(eng, CS_OPT_DETAIL, CS_OPT_ON);
        ptr = blob.data() + off;
        len = blob.size() - off;
        size_t cnt = cs_disasm(eng, ptr, len, 0, lim, &inst);
        if (cnt == 0) fatal("disasm fail");

        std::string pattern = instructions_to_pattern(arc, inst, cnt);
        std::vector<uint8_t> raw;
        for (size_t idx = 0; idx < cnt; ++idx)
            raw.insert(raw.end(), inst[idx].bytes, inst[idx].bytes + inst[idx].size);

        cs_free(inst, cnt);
        cs_close(&eng);
        return {pattern, raw};
    }

    // Parse exact hex string into bytes (no wildcards allowed)
    std::vector<uint8_t> parse_hex_exact(const std::string &s) {
        std::istringstream stream(s);
        std::string token;
        std::vector<uint8_t> out;
        while (stream >> token) {
            if (token.find('?') != std::string::npos) fatal("wildcards not allowed in hex input");
            out.push_back(static_cast<uint8_t>(std::stoul(token, nullptr, 16)));
        }
        return out;
    }

    std::string apple_signature_from_hex(const std::string &hex) {
        std::vector<uint8_t> bytes = parse_hex_exact(hex);
        if (bytes.empty()) fatal("hex input required");

        csh eng;
        cs_insn *inst;
        if (cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &eng) != CS_ERR_OK) fatal("capstone fail");
        cs_option(eng, CS_OPT_DETAIL, CS_OPT_ON);

        size_t cnt = cs_disasm(eng, bytes.data(), bytes.size(), 0, 0, &inst);
        if (cnt == 0) fatal("unable to disassemble input");

        std::string pattern = instructions_to_pattern(CS_ARCH_AARCH64, inst, cnt);

        cs_free(inst, cnt);
        cs_close(&eng);
        return pattern;
    }

    // Match signature to address
    bool sig_match(const std::vector<uint8_t> &hay, const std::vector<uint8_t> &pat) {
        size_t i, j;
        bool same;
        for (i = 0; i + pat.size() <= hay.size(); i++) {
            same = true;
            for (j = 0; j < pat.size(); j++) {
                if (pat[j] != 0xFF && pat[j] != hay[i + j]) {
                    same = false;
                    break;
                }
            }
            if (same) {
                std::lock_guard<std::mutex> lk(lock);
                std::cout << clr_ok << "[+] match @ 0x" << std::hex << i << clr_rst << std::endl;
                return true;
            }
        }
        return false;
    }

    // Display help message
    void helpme() {
        std::cout << clr_hdr << "usage:\n" << clr_rst;
        std::cout << clr_alt << "  ./sig bin --addr-to-sig 0xFFFF\n";
        std::cout << "  ./sig bin --sig-to-addr " << clr_ok << "AA BB ?? CC" << clr_rst << '\n';
        std::cout << "  ./sig " << clr_ok << "--hex-to-apple" << clr_rst << " " << clr_alt << "AA BB CC" << clr_rst << std::endl;
    }

public:
    void run(int ac, char **av) {
        if (ac < 2 || std::string(av[1]) == "--help") {
            helpme();
            return;
        }

        std::string first = av[1];
        if (first == "--hex-to-apple") {
            if (ac < 3) fatal("hex string required");
            std::stringstream ss;
            for (int i = 2; i < ac; ++i) ss << av[i] << ' ';
            std::string pattern = apple_signature_from_hex(ss.str());
            std::cout << clr_ok << "[apple]" << clr_rst << " " << pattern << std::endl;
            return;
        }

        if (!fileExists(first)) fatal("no such file");

        std::vector<uint8_t> buf = bin_load(first);

        if (ac >= 4) {
            std::string flg = av[2];
            if (flg == "--addr-to-sig") {
                size_t ofs = std::stoul(av[3], nullptr, 16);
                if (ofs >= buf.size()) fatal("offset out of range");
                auto [pattern, raw] = bin_disasm_pattern(buf, ofs, 5);
                std::cout << clr_hdr << "raw:" << clr_rst << '\n' << bin_hex(raw) << std::endl;
                std::cout << clr_ok << "apple:" << clr_rst << '\n' << pattern << std::endl;
            } else if (flg == "--sig-to-addr") {
                std::stringstream ss;
                for (int i = 3; i < ac; i++) ss << av[i] << ' ';
                auto sig = sig_parse(ss.str());
                sig_match(buf, sig);
            } else {
                fatal("bad flag");
            }
        } else {
            fatal("not enough args");
        }
    }
};

int main(int argc, char **argv) {
    iSig disasmtargetdshit;
    disasmtargetdshit.run(argc, argv);
    return 0;
}