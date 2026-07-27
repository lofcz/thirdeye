#ifndef THIRDEYE_SBOX_SHRED_H
#define THIRDEYE_SBOX_SHRED_H

#include <cstdint>
#include <cstring>
#include <string>

namespace shred_detail {

namespace aes {

constexpr uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        bool hi = a & 0x80; a <<= 1;
        if (hi) a ^= 0x1B; b >>= 1;
    }
    return p;
}

constexpr uint8_t gpow(uint8_t a, int e) {
    uint8_t r = 1;
    for (int i = 0; i < e; i++) r = gmul(r, a);
    return r;
}

constexpr uint8_t rotl8(uint8_t x, int n) {
    return (uint8_t)((x << n) | (x >> (8 - n)));
}

constexpr uint8_t AffineSeedByte(int which) {
    const char* seed = "thirdeye.sbox.v1";
    uint8_t v = 0;
    for (int i = 0; seed[i]; i++) v = (uint8_t)((v * 31) + (uint8_t)seed[i]);
    return (uint8_t)(v ^ (0xA7 + which * 0x9E) ^ (which * 0x37));
}

constexpr uint8_t ComputeSBoxEntry(uint8_t x) {
    uint8_t inv = (x == 0) ? 0 : gpow(x, 254);
    uint8_t c = AffineSeedByte(0);
    return (uint8_t)(inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ c);
}

struct SBoxTables {
    uint8_t fwd[256];
    uint8_t inv[256];
    constexpr SBoxTables() : fwd{}, inv{} {
        for (int i = 0; i < 256; i++) fwd[i] = ComputeSBoxEntry((uint8_t)i);
        for (int i = 0; i < 256; i++) inv[fwd[i]] = (uint8_t)i;
    }
};

constexpr SBoxTables kTables{};

constexpr uint8_t MakeRcon(int i) {
    const char* seed = "thirdeye.rcon.v1";
    uint8_t v = (uint8_t)(0x5A ^ (i * 0x1D));
    for (int k = 0; seed[k]; k++) v = (uint8_t)((v * 17) ^ (uint8_t)seed[k] ^ (uint8_t)i);
    return v ? v : 0xA5;
}

constexpr uint8_t rcon[11] = {
    MakeRcon(0), MakeRcon(1), MakeRcon(2), MakeRcon(3), MakeRcon(4),
    MakeRcon(5), MakeRcon(6), MakeRcon(7), MakeRcon(8), MakeRcon(9), MakeRcon(10)
};

constexpr void KeyExpansion(const uint8_t* key, uint8_t* w) {
    for (int i = 0; i < 4; i++) {
        w[4 * i] = key[4 * i]; w[4 * i + 1] = key[4 * i + 1];
        w[4 * i + 2] = key[4 * i + 2]; w[4 * i + 3] = key[4 * i + 3];
    }
    for (int i = 4; i < 44; i++) {
        uint8_t temp[4] = { w[4 * (i - 1)], w[4 * (i - 1) + 1], w[4 * (i - 1) + 2], w[4 * (i - 1) + 3] };
        if (i % 4 == 0) {
            uint8_t t = temp[0];
            temp[0] = kTables.fwd[temp[1]] ^ rcon[i / 4]; temp[1] = kTables.fwd[temp[2]];
            temp[2] = kTables.fwd[temp[3]]; temp[3] = kTables.fwd[t];
        }
        w[4 * i] = w[4 * (i - 4)] ^ temp[0]; w[4 * i + 1] = w[4 * (i - 4) + 1] ^ temp[1];
        w[4 * i + 2] = w[4 * (i - 4) + 2] ^ temp[2]; w[4 * i + 3] = w[4 * (i - 4) + 3] ^ temp[3];
    }
}

constexpr void AddRoundKey(uint8_t* state, const uint8_t* roundKey) {
    for (int i = 0; i < 16; i++) state[i] ^= roundKey[i];
}
constexpr void SubBytes(uint8_t* state) { for (int i = 0; i < 16; i++) state[i] = kTables.fwd[state[i]]; }
constexpr void InvSubBytes(uint8_t* state) { for (int i = 0; i < 16; i++) state[i] = kTables.inv[state[i]]; }

constexpr void ShiftRows(uint8_t* state) {
    uint8_t t[16] = {};
    for (int i = 0; i < 16; i++) t[i] = state[i];
    state[1] = t[5]; state[5] = t[9]; state[9] = t[13]; state[13] = t[1];
    state[2] = t[10]; state[6] = t[14]; state[10] = t[2]; state[14] = t[6];
    state[3] = t[15]; state[7] = t[3]; state[11] = t[7]; state[15] = t[11];
}
constexpr void InvShiftRows(uint8_t* state) {
    uint8_t t[16] = {};
    for (int i = 0; i < 16; i++) t[i] = state[i];
    state[1] = t[13]; state[5] = t[1]; state[9] = t[5]; state[13] = t[9];
    state[2] = t[10]; state[6] = t[14]; state[10] = t[2]; state[14] = t[6];
    state[3] = t[7]; state[7] = t[11]; state[11] = t[15]; state[15] = t[3];
}

constexpr void MixColumns(uint8_t* state) {
    uint8_t t[16] = {}; for (int i = 0; i < 16; i++) t[i] = state[i];
    for (int i = 0; i < 4; i++) {
        state[4*i]   = gmul(t[4*i], 2) ^ gmul(t[4*i+1], 3) ^ t[4*i+2] ^ t[4*i+3];
        state[4*i+1] = t[4*i] ^ gmul(t[4*i+1], 2) ^ gmul(t[4*i+2], 3) ^ t[4*i+3];
        state[4*i+2] = t[4*i] ^ t[4*i+1] ^ gmul(t[4*i+2], 2) ^ gmul(t[4*i+3], 3);
        state[4*i+3] = gmul(t[4*i], 3) ^ t[4*i+1] ^ t[4*i+2] ^ gmul(t[4*i+3], 2);
    }
}
constexpr void InvMixColumns(uint8_t* state) {
    uint8_t t[16] = {}; for (int i = 0; i < 16; i++) t[i] = state[i];
    for (int i = 0; i < 4; i++) {
        state[4*i]   = gmul(t[4*i], 0x0e) ^ gmul(t[4*i+1], 0x0b) ^ gmul(t[4*i+2], 0x0d) ^ gmul(t[4*i+3], 0x09);
        state[4*i+1] = gmul(t[4*i], 0x09) ^ gmul(t[4*i+1], 0x0e) ^ gmul(t[4*i+2], 0x0b) ^ gmul(t[4*i+3], 0x0d);
        state[4*i+2] = gmul(t[4*i], 0x0d) ^ gmul(t[4*i+1], 0x09) ^ gmul(t[4*i+2], 0x0e) ^ gmul(t[4*i+3], 0x0b);
        state[4*i+3] = gmul(t[4*i], 0x0b) ^ gmul(t[4*i+1], 0x0d) ^ gmul(t[4*i+2], 0x09) ^ gmul(t[4*i+3], 0x0e);
    }
}

constexpr void EncryptBlock(uint8_t* in, const uint8_t* key) {
    uint8_t w[176] = {}; KeyExpansion(key, w);
    AddRoundKey(in, w);
    for (int r = 1; r < 10; r++) { SubBytes(in); ShiftRows(in); MixColumns(in); AddRoundKey(in, w + r * 16); }
    SubBytes(in); ShiftRows(in); AddRoundKey(in, w + 160);
}
constexpr void DecryptBlock(uint8_t* in, const uint8_t* key) {
    uint8_t w[176] = {}; KeyExpansion(key, w);
    AddRoundKey(in, w + 160);
    for (int r = 9; r > 0; r--) { InvShiftRows(in); InvSubBytes(in); AddRoundKey(in, w + r * 16); InvMixColumns(in); }
    InvShiftRows(in); InvSubBytes(in); AddRoundKey(in, w);
}

}

constexpr uint64_t FnvBasis(uint64_t round) {
    return 0xcbf29ce484222325ull ^ (round * 0x9e3779b97f4a7c15ull);
}
constexpr uint64_t FnvStep(uint64_t h, uint8_t b) {
    return (h ^ b) * 0x100000001b3ull;
}
constexpr uint64_t HashBytes(uint64_t h, const char* s) {
    while (*s) { h = FnvStep(h, (uint8_t)*s); ++s; }
    return h;
}
constexpr uint64_t HashUint(uint64_t h, uint64_t v) {
    for (int i = 0; i < 8; ++i) { h = FnvStep(h, (uint8_t)(v & 0xff)); v >>= 8; }
    return h;
}

constexpr uint64_t NameHash() {
#ifdef __FILE_NAME__
    return HashBytes(FnvBasis(2), __FILE_NAME__);
#else
    const char* f = __FILE__; const char* base = f;
    for (const char* p = f; *p; ++p)
        if (*p == '/' || *p == '\\') base = p + 1;
    return HashBytes(FnvBasis(2), base);
#endif
}

template <uint64_t NAME_H, uint64_t CNT, uint64_t LINE>
struct LiteralKey {
    static constexpr uint64_t Build() {
        uint64_t h = FnvBasis(0);
        h ^= NAME_H * 0x9e3779b97f4a7c15ull;
        h = HashUint(h, CNT);
        h = HashUint(h, LINE);
        h = HashUint(h, NAME_H ^ 0xddbeffcfebbull);
        return h;
    }
    static constexpr uint64_t Build2() {
        uint64_t h = FnvBasis(1);
        h ^= NAME_H;
        h = HashUint(h, LINE * 0x100000001b3ull);
        h = HashUint(h, CNT * 0x9e3779b97f4a7c15ull);
        h = HashUint(h, NAME_H ^ 0x0123456789abcdefull);
        return h;
    }
    static constexpr void Fill(uint8_t* out) {
        uint64_t a = Build(), b = Build2();
        for (int i = 0; i < 8; ++i) { out[i] = (uint8_t)(a & 0xff); a >>= 8; }
        for (int i = 0; i < 8; ++i) { out[8 + i] = (uint8_t)(b & 0xff); b >>= 8; }
    }
};

template <size_t N, uint64_t NAME_H, uint64_t CNT, uint64_t LINE>
struct Shredded {
    uint8_t data[((N + 15) / 16) * 16];
    uint8_t key[16];
    size_t len;

    constexpr Shredded(const char (&str)[N]) : data{}, key{}, len(N) {
        LiteralKey<NAME_H, CNT, LINE>::Fill(key);
        for (size_t i = 0; i < N; ++i) data[i] = (uint8_t)str[i];
        for (size_t b = 0; b < (N + 15) / 16; ++b) {
            aes::EncryptBlock(&data[b * 16], key);
        }

        uint8_t check[sizeof(data)] = {};
        for (size_t i = 0; i < sizeof(data); ++i) check[i] = data[i];
        for (size_t b = 0; b < sizeof(check) / 16; ++b) {
            aes::DecryptBlock(&check[b * 16], key);
        }
        for (size_t i = 0; i < N; ++i) {
            int ok = (check[i] == (uint8_t)str[i]) ? 1 : 0;
            (void)(1 / ok);
        }
    }

    void reveal(char* out) const {
        uint8_t tmp[sizeof(data)];
        std::memcpy(tmp, data, sizeof(tmp));
        for (size_t b = 0; b < sizeof(tmp) / 16; ++b) {
            aes::DecryptBlock(&tmp[b * 16], key);
        }
        std::memcpy(out, tmp, len);
        out[len - 1] = '\0';

        volatile uint8_t* p = tmp;
        for (size_t i = 0; i < sizeof(tmp); ++i) p[i] = 0;
    }
};

}

#define SHRED(str) shred_detail::Shredded<sizeof(str), \
    shred_detail::NameHash(), (uint64_t)__COUNTER__, (uint64_t)__LINE__>(str)

#define REVEAL_CSTR(shredded) ([&]() -> const char* { \
    static thread_local char _buf[sizeof((shredded).data) + 1]; \
    (shredded).reveal(_buf); \
    return _buf; \
}())

#define REVEAL_STR(shredded) std::string(REVEAL_CSTR(shredded))

#endif
