#include "ByteSearch.h"
#include "Log.h"
#include <cstdint>
#include <psapi.h>
#include <string>
#include <vector>

// ---- parse "48 8B ?? C4" → bytes + mask ----
static bool ParseSignature(const char* str, std::vector<uint8_t>& bytes, std::vector<uint8_t>& mask)
{
    bytes.clear();
    mask.clear();

    for (const char* p = str; *p; ) {
        // skip delimiters
        if (*p == ' ' || *p == '\t' || *p == ',') { ++p; continue; }

        if (p[0] == '?' && p[1] == '?') {
            bytes.push_back(0);
            mask.push_back(0);       // 0 = wildcard
            p += 2;
            continue;
        }

        // expect two hex digits
        char hi = p[0], lo = p[1];
        if (!hi || !lo) return false;

        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int h = nib(hi), l = nib(lo);
        if (h < 0 || l < 0) return false;

        bytes.push_back((uint8_t)((h << 4) | l));
        mask.push_back(1);           // 1 = must match
        p += 2;
    }
    return !bytes.empty();
}

// ---- internal: single-sig scan with parsed bytes ----
static void* ScanOne(HMODULE module, const std::vector<uint8_t>& bytes,
                     const std::vector<uint8_t>& mask, int matchIndex)
{
    MODULEINFO modInfo{};
    if (!GetModuleInformation(GetCurrentProcess(), module, &modInfo, sizeof(MODULEINFO)))
        return nullptr;

    auto* base = static_cast<uint8_t*>(modInfo.lpBaseOfDll);
    SIZE_T size = modInfo.SizeOfImage;
    SIZE_T patLen = bytes.size();

    if (size < patLen) return nullptr;

    int currentMatch = 0;
    for (SIZE_T i = 0; i <= size - patLen; ++i) {
        bool found = true;
        for (SIZE_T j = 0; j < patLen; ++j) {
            if (mask[j] && base[i + j] != bytes[j]) {
                found = false;
                break;
            }
        }
        if (found && ++currentMatch == matchIndex) {
            return base + i;
        }
    }
    return nullptr;
}

// ---- multi-signature search ----
void* ByteSearch(HMODULE module, const char* funcName, std::initializer_list<Signature> sigs)
{
    std::vector<uint8_t> bytes, mask;

    for (const auto& sig : sigs) {
        if (!ParseSignature(sig.signature, bytes, mask)) {
            LOG_WARN("ByteSearch: {} — bad signature '{}'", funcName ? funcName : "", sig.label);
            continue;
        }
        void* addr = ScanOne(module, bytes, mask, sig.matchIndex);
        if (addr) {
            if (funcName)
                LOG_DEBUG("ByteSearch: {} matched '{}'", funcName, sig.label);
            return addr;
        }
    }

    // all failed
    if (!funcName) return nullptr;          // single-sig caller handles its own log

    std::string failedList;
    for (const auto& sig : sigs) {
        if (!failedList.empty()) failedList += ", ";
        failedList += "'";
        failedList += sig.label;
        failedList += "'";
    }
    LOG_WARN("ByteSearch FAILED: {} — tried: {}", funcName, failedList);
    return nullptr;
}

// ---- pointer + count overload ----
void* ByteSearch(HMODULE module, const char* funcName, const Signature* sigs, size_t count)
{
    std::vector<uint8_t> bytes, mask;

    for (size_t i = 0; i < count; ++i) {
        if (!ParseSignature(sigs[i].signature, bytes, mask)) {
            LOG_WARN("ByteSearch: {} — bad signature '{}'", funcName ? funcName : "", sigs[i].label);
            continue;
        }
        void* addr = ScanOne(module, bytes, mask, sigs[i].matchIndex);
        if (addr) {
            if (funcName)
                LOG_DEBUG("ByteSearch: {} matched '{}'", funcName, sigs[i].label);
            return addr;
        }
    }

    if (!funcName) return nullptr;

    std::string failedList;
    for (size_t i = 0; i < count; ++i) {
        if (!failedList.empty()) failedList += ", ";
        failedList += "'";
        failedList += sigs[i].label;
        failedList += "'";
    }
    LOG_WARN("ByteSearch FAILED: {} — tried: {}", funcName, failedList);
    return nullptr;
}

// ---- memory patching ----
int PatchMemoryBytes(void* pAddress, const void* pNewBytes, SIZE_T nSize)
{
    if (!pAddress || !pNewBytes || nSize == 0) return 0;

    DWORD oldProtect = 0;
    if (!VirtualProtect(pAddress, nSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        return 0;

    memcpy(pAddress, pNewBytes, nSize);
    FlushInstructionCache(GetCurrentProcess(), pAddress, nSize);

    DWORD tmp = 0;
    VirtualProtect(pAddress, nSize, oldProtect, &tmp);
    return 1;
}
