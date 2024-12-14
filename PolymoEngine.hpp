#pragma once

//#include <vector>
//#include <string>
#include <random>
#include <utility>
#include <cstdint>

#pragma region XoroShiro128

class XoroShiro128 {
public:
    using result_type = uint64_t;
private:
    uint64_t s[2];

    static __forceinline uint64_t rotl(const uint64_t x, int k) {
        return (x << k) | (x >> (64 - k));
    }
public:
    XoroShiro128(uint64_t seed1 = 987654321, uint64_t seed2 = 1234567890) {
        s[0] = seed1, s[1] = seed2;
    }

    static constexpr result_type min() {
        return 0;
    }
    static constexpr result_type max() {
        return UINT64_MAX;
    }

    result_type operator()() {
        const uint64_t s0 = s[0];
        uint64_t s1 = s[1];
        const uint64_t result = rotl(s0 + s1, 17) + s0;

        s1 ^= s0;
        s[0] = rotl(s0, 49) ^ s1 ^ (s1 << 21); // a, b
        s[1] = rotl(s1, 28); // c

        return result;
    }
};

#pragma endregion

namespace Math {

    #pragma region Montgomery

    class Montgomery {
        uint64_t n;
        uint64_t nb;
        uint64_t r2;
        uint64_t mask;
        uint64_t nr;

        int bit_length(uint64_t x) {
            int length = 0;
            while (x > 0) {
                length++;
                x >>= 1;
            }
            return length;
        }
    public:
        Montgomery(uint64_t n) : n(n) {
            nb = bit_length(n);
            r2 = (1ULL << (nb * 2)) % n;
            mask = (1ULL << nb) - 1;
            nr = 0;
            uint64_t t = 0;
            uint64_t vi = 1;
            for (uint64_t i = 0; i < nb; ++i) {
                if ((t & 1) == 0) {
                    t += n;
                    nr += vi;
                }
                t >>= 1;
                vi <<= 1;
            }
        }

        uint64_t reduction(uint64_t t) {
            uint64_t c = (t * nr) & mask;
            c = (c * n + t) >> nb;
            if (c >= n) c -= n;
            return c;
        }

        uint64_t mul(uint64_t a, uint64_t b) {
            return reduction(reduction(a * b) * r2);
        }

        uint64_t exp(uint64_t a, uint64_t b) {
            uint64_t p = reduction(a * r2);
            uint64_t x = reduction(r2);
            while (b > 0) {
                if (b & 1) x = reduction(x * p);
                p = reduction(p * p);
                b >>= 1;
            }
            return reduction(x);
        }
    };

    #pragma endregion

    #pragma region MillerRabin

    bool MillerRabin(uint64_t N, std::vector<uint64_t> A) {
        uint64_t s = 0, d = N - 1;
        while (d % 2 == 0) {
            ++s;
            d >>= 1;
        }
        for (auto a : A) {
            if (N <= a) return true;
            Montgomery mont(N);
            uint64_t t, x = mont.exp(a, d);
            if (x != 1) {
                for (t = 0; t < s; ++t) {
                    if (x == N - 1) break;
                    x = (x) * x % N;
                }
                if (t == s) return false;
            }
        }
        return true;
    }

    #pragma endregion

    #pragma region IsPrime

    bool is_prime(uint64_t N) {
        if (N <= 1ULL)          return false;
        if (N == 2ULL)          return true;
        if ((N & 1ULL) == 0ULL) return false;
        if (N < 4759123141ULL)
            return Math::MillerRabin(N, {2, 7, 61});
        else
            return Math::MillerRabin(N, {2, 325, 9375, 28178, 450775, 9780504, 1795265022});
    }

    #pragma endregion

    #pragma region Prime Generator

    uint64_t prime_gen(int bits) {
        uint64_t result;
        uint64_t seed[2];
        std::random_device seed_gen;
    re_seed:
        seed[0] = seed_gen() * (seed_gen() % 1000);
        seed[1] = seed_gen() * (seed_gen() % 1000);
        XoroShiro128 Engine(seed[0], seed[1]);

        int max_value = (1 << bits) - 1;
        int min_value = (1 << (bits-2)) - 1;
        std::uniform_int_distribution<> dis(min_value, max_value);

    loop:
        result = dis(Engine);
        if (result == 0)
            goto re_seed;
        if (!is_prime(result))
            goto loop;

        return result;
    }

    #pragma endregion

    #pragma region Random Generator

    uint64_t rand_gen(int min = 0, int max = 65535) {
        uint64_t seed[2];
        std::random_device seed_gen;
        seed[0] = seed_gen() * (seed_gen() % 1000);
        seed[1] = seed_gen() * (seed_gen() % 1000);
        XoroShiro128 Engine(seed[0], seed[1]);
        std::uniform_int_distribution<> dis(min, max);
        return dis(Engine);
    }

    #pragma endregion

    namespace Crypto {

        bool Crypto = false;
        static uint64_t p, g, y, x;

        #pragma region Elgamal Gen key

        void Elgamal_Gen_key(int bits = 16) {
            uint64_t q;
            while (1) {
                q = Math::prime_gen(bits-1);
                Crypto::p = 2*q + 1;
                if (Math::is_prime(p))
                    break;
            }
            Montgomery mont(Crypto::p);
            while (1) {
                g = Math::rand_gen(3, p);
                if (mont.exp(Crypto::g, 2ULL) == 1)
                    continue;
                if (mont.exp(Crypto::g, q) == 1)
                    continue;
                break;
            }
            Crypto::x = Math::rand_gen(2, Crypto::p-1);
            Crypto::y = mont.exp(Crypto::g, Crypto::x);
        }

        #pragma endregion

        #pragma region ElGamal Encrypt

        std::pair<uint64_t, uint64_t> ElGamal_Encrypt(uint64_t m) {
            if (!Math::Crypto::Crypto)
                exit(1);
            Montgomery mont(Crypto::p);
            uint64_t r = rand_gen(2, Crypto::p-1);
            uint64_t c1 = mont.exp(Crypto::g, r);
            uint64_t c2 = (m * mont.exp(Crypto::y, r)) % Crypto::p;
            return {c1, c2};
        }

        #pragma endregion

        #pragma region ElGamal Decrypt

        uint64_t ElGamal_Decrypt(uint64_t c1, uint64_t c2) {
            Montgomery mont(Crypto::p);
            return (c2 * mont.exp(c1, Crypto::p - 1 - x)) % Crypto::p;
        }

        #pragma endregion
    };
};

namespace Polymo {

    //Вызывается при инициализации ключа шифра ElGamal.
    //В основном вызывается только один раз.
    void InitPolymoEngine() {
        Math::Crypto::Crypto = true;
        Math::Crypto::Elgamal_Gen_key(32);
    }

    #pragma region _int8

    class _int8 {
        uint64_t c1, c2;
    public:
        __forceinline __fastcall _int8(int8_t num = 0) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(num);
            c1 = a, c2 = b;
        }

        __forceinline int8_t __fastcall get() const {
            return Math::Crypto::ElGamal_Decrypt(c1, c2);
        }

        __forceinline void __fastcall set(int8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(num);
            c1 = a, c2 = b;
        }

        __forceinline _int8 __fastcall operator+(const int8_t num) const {
            return _int8(Math::Crypto::ElGamal_Decrypt(c1, c2) + num);
        }

        __forceinline _int8 __fastcall operator-(const int8_t num) const {
            return _int8(Math::Crypto::ElGamal_Decrypt(c1, c2) - num);
        }

        __forceinline _int8 __fastcall operator*(const int8_t num) const {
            return _int8(Math::Crypto::ElGamal_Decrypt(c1, c2) * num);
        }

        __forceinline _int8 __fastcall operator/(const int8_t num) const {
            return _int8(Math::Crypto::ElGamal_Decrypt(c1, c2) / num);
        }

        __forceinline _int8 __fastcall operator%(const int8_t num) const {
            return _int8(Math::Crypto::ElGamal_Decrypt(c1, c2) % num);
        }

        __forceinline _int8 __fastcall operator&(const int8_t num) const {
            return _int8(Math::Crypto::ElGamal_Decrypt(c1, c2) & num);
        }

        __forceinline _int8 __fastcall operator|(const int8_t num) const {
            return _int8(Math::Crypto::ElGamal_Decrypt(c1, c2) | num);
        }

        __forceinline _int8 __fastcall operator^(const int8_t num) const {
            return _int8(Math::Crypto::ElGamal_Decrypt(c1, c2) ^ num);
        }

        __forceinline _int8 __fastcall operator<<(const int8_t num) const {
            return _int8(Math::Crypto::ElGamal_Decrypt(c1, c2) << num);
        }

        __forceinline _int8 __fastcall operator>>(const int8_t num) const {
            return _int8(Math::Crypto::ElGamal_Decrypt(c1, c2) >> num);
        }

        __forceinline _int8& __fastcall operator+=(const int8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) + num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _int8& __fastcall operator-=(const int8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) - num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _int8& __fastcall operator*=(const int8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) * num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _int8& __fastcall operator/=(const int8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) / num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _int8& __fastcall operator%=(const int8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) % num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _int8& __fastcall operator&=(const int8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) & num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _int8& __fastcall operator|=(const int8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) | num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _int8& __fastcall operator^=(const int8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) ^ num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _int8& __fastcall operator<<=(const int8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) << num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _int8& __fastcall operator>>=(const int8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) >> num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _int8& __fastcall operator=(const int8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline __fastcall operator char() const {
            return static_cast<int8_t>(Math::Crypto::ElGamal_Decrypt(c1, c2));
        }
    };

    #pragma endregion

    #pragma region _uint8

    class _uint8 {
        uint64_t c1, c2;
    public:
        __forceinline __fastcall _uint8(uint8_t num = 0) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(num);
            c1 = a, c2 = b;
        }

        __forceinline uint8_t __fastcall get() const {
            return Math::Crypto::ElGamal_Decrypt(c1, c2);
        }

        __forceinline void __fastcall set(uint8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(num);
            c1 = a, c2 = b;
        }

        __forceinline _uint8 __fastcall operator+(const uint8_t num) const {
            return _uint8(Math::Crypto::ElGamal_Decrypt(c1, c2) + num);
        }

        __forceinline _uint8 __fastcall operator-(const uint8_t num) const {
            return _uint8(Math::Crypto::ElGamal_Decrypt(c1, c2) - num);
        }

        __forceinline _uint8 __fastcall operator*(const uint8_t num) const {
            return _uint8(Math::Crypto::ElGamal_Decrypt(c1, c2) * num);
        }

        __forceinline _uint8 __fastcall operator/(const uint8_t num) const {
            return _uint8(Math::Crypto::ElGamal_Decrypt(c1, c2) / num);
        }

        __forceinline _uint8 __fastcall operator%(const uint8_t num) const {
            return _uint8(Math::Crypto::ElGamal_Decrypt(c1, c2) % num);
        }

        __forceinline _uint8 __fastcall operator&(const uint8_t num) const {
            return _uint8(Math::Crypto::ElGamal_Decrypt(c1, c2) & num);
        }

        __forceinline _uint8 __fastcall operator|(const uint8_t num) const {
            return _uint8(Math::Crypto::ElGamal_Decrypt(c1, c2) | num);
        }

        __forceinline _uint8 __fastcall operator^(const uint8_t num) const {
            return _uint8(Math::Crypto::ElGamal_Decrypt(c1, c2) ^ num);
        }

        __forceinline _uint8 __fastcall operator<<(const uint8_t num) const {
            return _uint8(Math::Crypto::ElGamal_Decrypt(c1, c2) << num);
        }

        __forceinline _uint8 __fastcall operator>>(const uint8_t num) const {
            return _uint8(Math::Crypto::ElGamal_Decrypt(c1, c2) >> num);
        }

        __forceinline _uint8& __fastcall operator+=(const uint8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) + num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _uint8& __fastcall operator-=(const uint8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) - num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _uint8& __fastcall operator*=(const uint8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) * num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _uint8& __fastcall operator/=(const uint8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) / num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _uint8& __fastcall operator%=(const uint8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) % num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _uint8& __fastcall operator&=(const uint8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) & num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _uint8& __fastcall operator|=(const uint8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) | num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _uint8& __fastcall operator^=(const uint8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) ^ num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _uint8& __fastcall operator<<=(const uint8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) << num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _uint8& __fastcall operator>>=(const uint8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) >> num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _uint8& __fastcall operator=(const uint8_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline __fastcall operator unsigned char() const {
            return static_cast<uint8_t>(Math::Crypto::ElGamal_Decrypt(c1, c2));
        }
    };

    #pragma endregion

    #pragma region _int16

    class _int16 {
        uint64_t c1, c2;
    public:
        __forceinline __fastcall _int16(int16_t num = 0) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(num);
            c1 = a, c2 = b;
        }

        __forceinline int16_t __fastcall get() const {
            return Math::Crypto::ElGamal_Decrypt(c1, c2);
        }

        __forceinline void __fastcall set(int16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(num);
            c1 = a, c2 = b;
        }

        __forceinline _int16 __fastcall operator+(const int16_t num) const {
            return _int16(Math::Crypto::ElGamal_Decrypt(c1, c2) + num);
        }

        __forceinline _int16 __fastcall operator-(const int16_t num) const {
            return _int16(Math::Crypto::ElGamal_Decrypt(c1, c2) - num);
        }

        __forceinline _int16 __fastcall operator*(const int16_t num) const {
            return _int16(Math::Crypto::ElGamal_Decrypt(c1, c2) * num);
        }

        __forceinline _int16 __fastcall operator/(const int16_t num) const {
            return _int16(Math::Crypto::ElGamal_Decrypt(c1, c2) / num);
        }

        __forceinline _int16 __fastcall operator%(const int16_t num) const {
            return _int16(Math::Crypto::ElGamal_Decrypt(c1, c2) % num);
        }

        __forceinline _int16 __fastcall operator&(const int16_t num) const {
            return _int16(Math::Crypto::ElGamal_Decrypt(c1, c2) & num);
        }

        __forceinline _int16 __fastcall operator|(const int16_t num) const {
            return _int16(Math::Crypto::ElGamal_Decrypt(c1, c2) | num);
        }

        __forceinline _int16 __fastcall operator^(const int16_t num) const {
            return _int16(Math::Crypto::ElGamal_Decrypt(c1, c2) ^ num);
        }

        __forceinline _int16 __fastcall operator<<(const int16_t num) const {
            return _int16(Math::Crypto::ElGamal_Decrypt(c1, c2) << num);
        }

        __forceinline _int16 __fastcall operator>>(const int16_t num) const {
            return _int16(Math::Crypto::ElGamal_Decrypt(c1, c2) >> num);
        }

        __forceinline _int16& __fastcall operator+=(const int16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) + num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _int16& __fastcall operator-=(const int16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) - num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _int16& __fastcall operator*=(const int16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) * num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _int16& __fastcall operator/=(const int16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) / num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _int16& __fastcall operator%=(const int16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) % num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _int16& __fastcall operator&=(const int16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) & num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _int16& __fastcall operator|=(const int16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) | num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _int16& __fastcall operator^=(const int16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) ^ num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _int16& __fastcall operator<<=(const int16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) << num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _int16& __fastcall operator>>=(const int16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) >> num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _int16& __fastcall operator=(const int16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline __fastcall operator short() const {
            return static_cast<int16_t>(Math::Crypto::ElGamal_Decrypt(c1, c2));
        }
    };

    #pragma endregion

    #pragma region _uint16

    class _uint16 {
        uint64_t c1, c2;
    public:
        __forceinline __fastcall _uint16(uint16_t num = 0) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(num);
            c1 = a, c2 = b;
        }

        __forceinline uint16_t __fastcall get() const {
            return Math::Crypto::ElGamal_Decrypt(c1, c2);
        }

        __forceinline void __fastcall set(uint16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(num);
            c1 = a, c2 = b;
        }

        __forceinline _uint16 __fastcall operator+(const uint16_t num) const {
            return _uint16(Math::Crypto::ElGamal_Decrypt(c1, c2) + num);
        }

        __forceinline _uint16 __fastcall operator-(const uint16_t num) const {
            return _uint16(Math::Crypto::ElGamal_Decrypt(c1, c2) - num);
        }

        __forceinline _uint16 __fastcall operator*(const uint16_t num) const {
            return _uint16(Math::Crypto::ElGamal_Decrypt(c1, c2) * num);
        }

        __forceinline _uint16 __fastcall operator/(const uint16_t num) const {
            return _uint16(Math::Crypto::ElGamal_Decrypt(c1, c2) / num);
        }

        __forceinline _uint16 __fastcall operator%(const uint16_t num) const {
            return _uint16(Math::Crypto::ElGamal_Decrypt(c1, c2) % num);
        }

        __forceinline _uint16 __fastcall operator&(const uint16_t num) const {
            return _uint16(Math::Crypto::ElGamal_Decrypt(c1, c2) & num);
        }

        __forceinline _uint16 __fastcall operator|(const uint16_t num) const {
            return _uint16(Math::Crypto::ElGamal_Decrypt(c1, c2) | num);
        }

        __forceinline _uint16 __fastcall operator^(const uint16_t num) const {
            return _uint16(Math::Crypto::ElGamal_Decrypt(c1, c2) ^ num);
        }

        __forceinline _uint16 __fastcall operator<<(const uint16_t num) const {
            return _uint16(Math::Crypto::ElGamal_Decrypt(c1, c2) << num);
        }

        __forceinline _uint16 __fastcall operator>>(const uint16_t num) const {
            return _uint16(Math::Crypto::ElGamal_Decrypt(c1, c2) >> num);
        }

        __forceinline _uint16& __fastcall operator+=(const uint16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) + num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _uint16& __fastcall operator-=(const uint16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) - num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _uint16& __fastcall operator*=(const uint16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) * num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _uint16& __fastcall operator/=(const uint16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) / num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _uint16& __fastcall operator%=(const uint16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) % num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _uint16& __fastcall operator&=(const uint16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) & num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _uint16& __fastcall operator|=(const uint16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) | num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _uint16& __fastcall operator^=(const uint16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) ^ num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _uint16& __fastcall operator<<=(const uint16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) << num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _uint16& __fastcall operator>>=(const uint16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) >> num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _uint16& __fastcall operator=(const uint16_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline __fastcall operator unsigned short() const {
            return static_cast<uint16_t>(Math::Crypto::ElGamal_Decrypt(c1, c2));
        }
    };

    #pragma endregion

    #pragma region _int32

    class _int32 {
        uint64_t temp[2];
        uint64_t c[2][2];

        void Encrypt(int32_t num) {
            temp[0] = num / 100000;
            temp[1] = num % 100000;
            for (int i = 0; i < 2; ++i) {
                auto [a, b] = Math::Crypto::ElGamal_Encrypt(temp[i]);
                c[i][0] = a;
                c[i][1] = b;
                temp[i] = 0;
            }
        }

        int32_t Decrypt() {
            int32_t m = 0;
            for (int i = 0; i < 2; ++i)
                temp[i] = Math::Crypto::ElGamal_Decrypt(c[i][0], c[i][1]);
            m = temp[0] * 100000;
            m += temp[1];
            temp[0] = temp[1] = 0;
            return m;
        }
    public:
        __forceinline __fastcall _int32(int32_t num = 0) {
            Encrypt(num);
        }

        __forceinline int32_t __fastcall get() {
            return Decrypt();
        }

        __forceinline void __fastcall set(int32_t num) {
            Encrypt(num);
        }

        __forceinline _int32 __fastcall operator+(const int32_t num) {
            return _int32(Decrypt() + num);
        }

        __forceinline _int32 __fastcall operator-(const int32_t num) {
            return _int32(Decrypt() - num);
        }

        __forceinline _int32 __fastcall operator*(const int32_t num) {
            return _int32(Decrypt() * num);
        }

        __forceinline _int32 __fastcall operator/(const int32_t num) {
            return _int32(Decrypt() / num);
        }

        __forceinline _int32 __fastcall operator%(const int32_t num) {
            return _int32(Decrypt() % num);
        }

        __forceinline _int32 __fastcall operator&(const int32_t num) {
            return _int32(Decrypt() & num);
        }

        __forceinline _int32 __fastcall operator|(const int32_t num) {
            return _int32(Decrypt() | num);
        }

        __forceinline _int32 __fastcall operator^(const int32_t num) {
            return _int32(Decrypt() ^ num);
        }

        __forceinline _int32 __fastcall operator<<(const int32_t num) {
            return _int32(Decrypt() << num);
        }

        __forceinline _int32 __fastcall operator>>(const int32_t num) {
            return _int32(Decrypt() >> num);
        }

        __forceinline _int32& __fastcall operator+=(const int32_t num) {
            Encrypt(Decrypt() + num);
            return *this;
        }

        __forceinline _int32& __fastcall operator-=(const int32_t num) {
            Encrypt(Decrypt() - num);
            return *this;
        }

        __forceinline _int32& __fastcall operator*=(const int32_t num) {
            Encrypt(Decrypt() * num);
            return *this;
        }

        __forceinline _int32& __fastcall operator/=(const int32_t num) {
            Encrypt(Decrypt() / num);
            return *this;
        }

        __forceinline _int32& __fastcall operator%=(const int32_t num) {
            Encrypt(Decrypt() % num);
            return *this;
        }

        __forceinline _int32& __fastcall operator&=(const int32_t num) {
            Encrypt(Decrypt() & num);
            return *this;
        }

        __forceinline _int32& __fastcall operator|=(const int32_t num) {
            Encrypt(Decrypt() | num);
            return *this;
        }

        __forceinline _int32& __fastcall operator^=(const int32_t num) {
            Encrypt(Decrypt() ^ num);
            return *this;
        }

        __forceinline _int32& __fastcall operator<<=(const int32_t num) {
            Encrypt(Decrypt() << num);
            return *this;
        }

        __forceinline _int32& __fastcall operator>>=(const int32_t num) {
            Encrypt(Decrypt() >> num);
            return *this;
        }

        __forceinline _int32& __fastcall operator=(const int32_t num) {
            Encrypt(num);
            return *this;
        }

        __forceinline __fastcall operator int() {
            return Decrypt();
        }
    };

    #pragma endregion

    #pragma region _uint32

    class _uint32 {
        uint64_t temp[2];
        uint64_t c[2][2];

        void Encrypt(uint32_t num) {
            temp[0] = num / 100000;
            temp[1] = num % 100000;
            for (int i = 0; i < 2; ++i) {
                auto [a, b] = Math::Crypto::ElGamal_Encrypt(temp[i]);
                c[i][0] = a;
                c[i][1] = b;
                temp[i] = 0;
            }
        }

        uint32_t Decrypt() {
            uint32_t m = 0;
            for (int i = 0; i < 2; ++i)
                temp[i] = Math::Crypto::ElGamal_Decrypt(c[i][0], c[i][1]);
            m = temp[0] * 100000;
            m += temp[1];
            temp[0] = temp[1] = 0;
            return m;
        }
    public:
        __forceinline __fastcall _uint32(uint32_t num = 0) {
            Encrypt(num);
        }

        __forceinline int32_t __fastcall get() {
            return Decrypt();
        }

        __forceinline void __fastcall set(uint32_t num) {
            Encrypt(num);
        }

        __forceinline _uint32 __fastcall operator+(const uint32_t num) {
            return _uint32(Decrypt() + num);
        }

        __forceinline _uint32 __fastcall operator-(const uint32_t num) {
            return _uint32(Decrypt() - num);
        }

        __forceinline _uint32 __fastcall operator*(const uint32_t num) {
            return _uint32(Decrypt() * num);
        }

        __forceinline _uint32 __fastcall operator/(const uint32_t num) {
            return _uint32(Decrypt() / num);
        }

        __forceinline _uint32 __fastcall operator%(const uint32_t num) {
            return _uint32(Decrypt() % num);
        }

        __forceinline _uint32 __fastcall operator&(const uint32_t num) {
            return _uint32(Decrypt() & num);
        }

        __forceinline _uint32 __fastcall operator|(const uint32_t num) {
            return _uint32(Decrypt() | num);
        }

        __forceinline _uint32 __fastcall operator^(const uint32_t num) {
            return _uint32(Decrypt() ^ num);
        }

        __forceinline _uint32 __fastcall operator<<(const uint32_t num) {
            return _uint32(Decrypt() << num);
        }

        __forceinline _uint32 __fastcall operator>>(const uint32_t num) {
            return _uint32(Decrypt() >> num);
        }

        __forceinline _uint32& __fastcall operator+=(const uint32_t num) {
            Encrypt(Decrypt() + num);
            return *this;
        }

        __forceinline _uint32& __fastcall operator-=(const uint32_t num) {
            Encrypt(Decrypt() - num);
            return *this;
        }

        __forceinline _uint32& __fastcall operator*=(const uint32_t num) {
            Encrypt(Decrypt() * num);
            return *this;
        }

        __forceinline _uint32& __fastcall operator/=(const uint32_t num) {
            Encrypt(Decrypt() / num);
            return *this;
        }

        __forceinline _uint32& __fastcall operator%=(const uint32_t num) {
            Encrypt(Decrypt() % num);
            return *this;
        }

        __forceinline _uint32& __fastcall operator&=(const uint32_t num) {
            Encrypt(Decrypt() & num);
            return *this;
        }

        __forceinline _uint32& __fastcall operator|=(const uint32_t num) {
            Encrypt(Decrypt() | num);
            return *this;
        }

        __forceinline _uint32& __fastcall operator^=(const uint32_t num) {
            Encrypt(Decrypt() ^ num);
            return *this;
        }

        __forceinline _uint32& __fastcall operator<<=(const uint32_t num) {
            Encrypt(Decrypt() << num);
            return *this;
        }

        __forceinline _uint32& __fastcall operator>>=(const uint32_t num) {
            Encrypt(Decrypt() >> num);
            return *this;
        }

        __forceinline _uint32& __fastcall operator=(const uint32_t num) {
            Encrypt(num);
            return *this;
        }

        __forceinline __fastcall operator unsigned int() {
            return Decrypt();
        }
    };

    #pragma endregion

    #pragma region _int64

    class _int64 {
        uint64_t temp[5];
        uint64_t c[5][2];

        int64_t pow(int64_t a, int64_t b) {
            int64_t res = 1;
            while (b > 0) {
                if (b & 1)
                    res *= a;
                a *= a;
                b >>= 1;
            }
            return res;
        }

        void Encrypt(int64_t num) {
            for (int i = 4; i >= 0; --i) {
                temp[i] = num % 100000;
                num /= 100000;
            }
            for (int i = 4; i >= 0; --i) {
                auto [a, b] = Math::Crypto::ElGamal_Encrypt(temp[i]);
                c[i][0] = a;
                c[i][1] = b;
                temp[i] = 0;
            }
        }

        int64_t Decrypt() {
            int64_t m = 0;
            for (int i = 0; i < 5; ++i)
                m += Math::Crypto::ElGamal_Decrypt(c[4-i][0], c[4-i][1]) * pow(100000, i);
            return m;
        }
    public:
        __forceinline __fastcall _int64(int64_t num = 0) {
            Encrypt(num);
        }

        __forceinline int64_t __fastcall get() {
            return Decrypt();
        }

        __forceinline void __fastcall set(int64_t num) {
            Encrypt(num);
        }

        __forceinline _int64 __fastcall operator+(const int64_t num) {
            return _int64(Decrypt() + num);
        }

        __forceinline _int64 __fastcall operator-(const int64_t num) {
            return _int64(Decrypt() - num);
        }

        __forceinline _int64 __fastcall operator*(const int64_t num) {
            return _int64(Decrypt() * num);
        }

        __forceinline _int64 __fastcall operator/(const int64_t num) {
            return _int64(Decrypt() / num);
        }

        __forceinline _int64 __fastcall operator%(const int64_t num) {
            return _int64(Decrypt() % num);
        }

        __forceinline _int64 __fastcall operator&(const int64_t num) {
            return _int64(Decrypt() & num);
        }

        __forceinline _int64 __fastcall operator|(const int64_t num) {
            return _int64(Decrypt() | num);
        }

        __forceinline _int64 __fastcall operator^(const int64_t num) {
            return _int64(Decrypt() ^ num);
        }

        __forceinline _int64 __fastcall operator<<(const int64_t num) {
            return _int64(Decrypt() << num);
        }

        __forceinline _int64 __fastcall operator>>(const int64_t num) {
            return _int64(Decrypt() >> num);
        }

        __forceinline _int64& __fastcall operator+=(const int64_t num) {
            Encrypt(Decrypt() + num);
            return *this;
        }

        __forceinline _int64& __fastcall operator-=(const int64_t num) {
            Encrypt(Decrypt() - num);
            return *this;
        }

        __forceinline _int64& __fastcall operator*=(const int64_t num) {
            Encrypt(Decrypt() * num);
            return *this;
        }

        __forceinline _int64& __fastcall operator/=(const int64_t num) {
            Encrypt(Decrypt() / num);
            return *this;
        }

        __forceinline _int64& __fastcall operator%=(const int64_t num) {
            Encrypt(Decrypt() % num);
            return *this;
        }

        __forceinline _int64& __fastcall operator&=(const int64_t num) {
            Encrypt(Decrypt() & num);
            return *this;
        }

        __forceinline _int64& __fastcall operator|=(const int64_t num) {
            Encrypt(Decrypt() | num);
            return *this;
        }

        __forceinline _int64& __fastcall operator^=(const int64_t num) {
            Encrypt(Decrypt() ^ num);
            return *this;
        }

        __forceinline _int64& __fastcall operator<<=(const int64_t num) {
            Encrypt(Decrypt() << num);
            return *this;
        }

        __forceinline _int64& __fastcall operator>>=(const int64_t num) {
            Encrypt(Decrypt() >> num);
            return *this;
        }

        __forceinline _int64& __fastcall operator=(const int64_t num) {
            Encrypt(num);
            return *this;
        }

        __forceinline __fastcall operator long long() {
            return Decrypt();
        }
    };

    #pragma endregion

    #pragma region _uint64

    class _uint64 {
        uint64_t temp[5];
        uint64_t c[5][2];

        uint64_t pow(uint64_t a, uint64_t b) {
            uint64_t res = 1;
            while (b > 0) {
                if (b & 1)
                    res *= a;
                a *= a;
                b >>= 1;
            }
            return res;
        }

        void Encrypt(uint64_t num) {
            for (int i = 4; i >= 0; --i) {
                temp[i] = num % 100000;
                num /= 100000;
            }
            for (int i = 4; i >= 0; --i) {
                auto [a, b] = Math::Crypto::ElGamal_Encrypt(temp[i]);
                c[i][0] = a;
                c[i][1] = b;
                temp[i] = 0;
            }
        }

        uint64_t Decrypt() {
            uint64_t m = 0;
            for (int i = 0; i < 5; ++i)
                m += Math::Crypto::ElGamal_Decrypt(c[4-i][0], c[4-i][1]) * pow(100000, i);
            return m;
        }
    public:
        __forceinline __fastcall _uint64(uint64_t num = 0) {
            Encrypt(num);
        }

        __forceinline uint64_t __fastcall get() {
            return Decrypt();
        }

        __forceinline void __fastcall set(uint64_t num) {
            Encrypt(num);
        }

        __forceinline _uint64 __fastcall operator+(const uint64_t num) {
            return _uint64(Decrypt() + num);
        }

        __forceinline _uint64 __fastcall operator-(const uint64_t num) {
            return _uint64(Decrypt() - num);
        }

        __forceinline _uint64 __fastcall operator*(const uint64_t num) {
            return _uint64(Decrypt() * num);
        }

        __forceinline _uint64 __fastcall operator/(const uint64_t num) {
            return _uint64(Decrypt() / num);
        }

        __forceinline _uint64 __fastcall operator%(const uint64_t num) {
            return _uint64(Decrypt() % num);
        }

        __forceinline _uint64 __fastcall operator&(const uint64_t num) {
            return _uint64(Decrypt() & num);
        }

        __forceinline _uint64 __fastcall operator|(const uint64_t num) {
            return _uint64(Decrypt() | num);
        }

        __forceinline _uint64 __fastcall operator^(const uint64_t num) {
            return _uint64(Decrypt() ^ num);
        }

        __forceinline _uint64 __fastcall operator<<(const uint64_t num) {
            return _uint64(Decrypt() << num);
        }

        __forceinline _uint64 __fastcall operator>>(const uint64_t num) {
            return _uint64(Decrypt() >> num);
        }

        __forceinline _uint64& __fastcall operator+=(const uint64_t num) {
            Encrypt(Decrypt() + num);
            return *this;
        }

        __forceinline _uint64& __fastcall operator-=(const uint64_t num) {
            Encrypt(Decrypt() - num);
            return *this;
        }

        __forceinline _uint64& __fastcall operator*=(const uint64_t num) {
            Encrypt(Decrypt() * num);
            return *this;
        }

        __forceinline _uint64& __fastcall operator/=(const uint64_t num) {
            Encrypt(Decrypt() / num);
            return *this;
        }

        __forceinline _uint64& __fastcall operator%=(const uint64_t num) {
            Encrypt(Decrypt() % num);
            return *this;
        }

        __forceinline _uint64& __fastcall operator&=(const uint64_t num) {
            Encrypt(Decrypt() & num);
            return *this;
        }

        __forceinline _uint64& __fastcall operator|=(const uint64_t num) {
            Encrypt(Decrypt() | num);
            return *this;
        }

        __forceinline _uint64& __fastcall operator^=(const uint64_t num) {
            Encrypt(Decrypt() ^ num);
            return *this;
        }

        __forceinline _uint64& __fastcall operator<<=(const uint64_t num) {
            Encrypt(Decrypt() << num);
            return *this;
        }

        __forceinline _uint64& __fastcall operator>>=(const uint64_t num) {
            Encrypt(Decrypt() >> num);
            return *this;
        }

        __forceinline _uint64& __fastcall operator=(const uint64_t num) {
            Encrypt(num);
            return *this;
        }

        __forceinline __fastcall operator unsigned long long() {
            return Decrypt();
        }
    };

    #pragma endregion

    #pragma region String

    class String {
        std::vector<_int8> c;

        void Encrypt(const std::string& str) {
            c.resize(str.length());
            for (size_t i = 0; i < str.length(); ++i)
                c[i] = str[i];
        }

        std::string Decrypt() {
            std::string m;
            for (size_t i = 0; i < c.size(); ++i)
                m += c[i];
            return m;
        }
    public:
        __forceinline __fastcall String(const std::string& str) {
            Encrypt(str);
        }

        __forceinline __fastcall String(const char* str) {
            Encrypt(str);
        }

        __forceinline std::string __fastcall get() {
            return Decrypt();
        }

        __forceinline void __fastcall set(const std::string& str) {
            Encrypt(str);
        }

        __forceinline String __fastcall operator+(const std::string& str) {
            return String(Decrypt() + str);
        }

        __forceinline String& __fastcall operator+=(const std::string& str) {
            Encrypt(Decrypt() + str);
            return *this;
        }

        __forceinline String& __fastcall operator=(const std::string& str) {
            set(str);
            return *this;
        }

        __forceinline char& __fastcall operator[](const int index) {
            return Decrypt()[index];
        }

        __forceinline const char* __fastcall c_str() {
            return Decrypt().c_str();
        }

        __forceinline __fastcall operator std::string() {
            return Decrypt();
        }

        __forceinline __fastcall ~String() {
            c.resize(0);
        }
    };

    #pragma endregion

    #pragma region _wchar

    class _wchar {
        uint64_t c1, c2;
    public:
        __forceinline __fastcall _wchar(wchar_t num = 0) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(num);
            c1 = a, c2 = b;
        }

        __forceinline wchar_t __fastcall get() const {
            return Math::Crypto::ElGamal_Decrypt(c1, c2);
        }

        __forceinline void __fastcall set(wchar_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(num);
            c1 = a, c2 = b;
        }

        __forceinline _wchar __fastcall operator+(const wchar_t num) const {
            return _wchar(Math::Crypto::ElGamal_Decrypt(c1, c2) + num);
        }

        __forceinline _wchar __fastcall operator-(const wchar_t num) const {
            return _wchar(Math::Crypto::ElGamal_Decrypt(c1, c2) - num);
        }

        __forceinline _wchar __fastcall operator*(const wchar_t num) const {
            return _wchar(Math::Crypto::ElGamal_Decrypt(c1, c2) * num);
        }

        __forceinline _wchar __fastcall operator/(const wchar_t num) const {
            return _wchar(Math::Crypto::ElGamal_Decrypt(c1, c2) / num);
        }

        __forceinline _wchar __fastcall operator%(const wchar_t num) const {
            return _wchar(Math::Crypto::ElGamal_Decrypt(c1, c2) % num);
        }

        __forceinline _wchar __fastcall operator&(const wchar_t num) const {
            return _wchar(Math::Crypto::ElGamal_Decrypt(c1, c2) & num);
        }

        __forceinline _wchar __fastcall operator|(const wchar_t num) const {
            return _wchar(Math::Crypto::ElGamal_Decrypt(c1, c2) | num);
        }

        __forceinline _wchar __fastcall operator^(const wchar_t num) const {
            return _wchar(Math::Crypto::ElGamal_Decrypt(c1, c2) ^ num);
        }

        __forceinline _wchar __fastcall operator<<(const wchar_t num) const {
            return _wchar(Math::Crypto::ElGamal_Decrypt(c1, c2) << num);
        }

        __forceinline _wchar __fastcall operator>>(const wchar_t num) const {
            return _wchar(Math::Crypto::ElGamal_Decrypt(c1, c2) >> num);
        }

        __forceinline _wchar& __fastcall operator+=(const wchar_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) + num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _wchar& __fastcall operator-=(const wchar_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) - num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _wchar& __fastcall operator*=(const wchar_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) * num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _wchar& __fastcall operator/=(const wchar_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) / num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _wchar& __fastcall operator%=(const wchar_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) % num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _wchar& __fastcall operator&=(const wchar_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) & num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _wchar& __fastcall operator|=(const wchar_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) | num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _wchar& __fastcall operator^=(const wchar_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) ^ num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _wchar& __fastcall operator<<=(const wchar_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) << num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _wchar& __fastcall operator>>=(const wchar_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(Math::Crypto::ElGamal_Decrypt(c1, c2) >> num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline _wchar& __fastcall operator=(const wchar_t num) {
            auto [a, b] = Math::Crypto::ElGamal_Encrypt(num);
            c1 = a, c2 = b;
            return *this;
        }

        __forceinline __fastcall operator wchar_t() const {
            return static_cast<wchar_t>(Math::Crypto::ElGamal_Decrypt(c1, c2));
        }
    };

    #pragma endregion

    #pragma region StringW

    class StringW {
        std::vector<_wchar> c;

        void Encrypt(const std::wstring& str) {
            c.resize(str.length());
            for (size_t i = 0; i < str.length(); ++i)
                c[i] = str[i];
        }

        std::wstring Decrypt() {
            std::wstring m;
            for (size_t i = 0; i < c.size(); ++i)
                m += c[i];
            return m;
        }
    public:
        __forceinline __fastcall StringW(const std::wstring& str) {
            Encrypt(str);
        }

        __forceinline __fastcall StringW(const wchar_t* str) {
            Encrypt(str);
        }

        __forceinline std::wstring __fastcall get() {
            return Decrypt();
        }

        __forceinline void __fastcall set(const std::wstring& str) {
            Encrypt(str);
        }

        __forceinline StringW __fastcall operator+(const std::wstring& str) {
            return StringW(Decrypt() + str);
        }

        __forceinline StringW& __fastcall operator+=(const std::wstring& str) {
            Encrypt(Decrypt() + str);
            return *this;
        }

        __forceinline StringW& __fastcall operator=(const std::wstring& str) {
            set(str);
            return *this;
        }

        __forceinline wchar_t& __fastcall operator[](const int index) {
            return Decrypt()[index];
        }

        __forceinline __fastcall operator std::wstring() {
            return Decrypt();
        }

        __forceinline __fastcall ~StringW() {
            c.resize(0);
        }
    };

    #pragma endregion
}
