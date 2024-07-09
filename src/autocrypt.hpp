#pragma once

#include <array>
#include <cstdint>
#include <string_view>

#define AUTOCRYPT_INLINE __forceinline

namespace autocrypt {

    constexpr size_t kNumStates = 32;
    constexpr size_t kAlphabetSize = 256;
    constexpr size_t kMaxStringLength = 1024;
    constexpr size_t kNumLayers = 3;

    struct ComplexDFA {
        std::array<std::array<std::array<uint8_t, kAlphabetSize>, kNumStates>, kNumLayers> transitions{};
        std::array<std::array<uint8_t, kNumStates>, kNumLayers> output{};
        std::array<uint8_t, kNumLayers> initial_state{};
    };

    struct EncryptedData {
        std::array<uint8_t, kMaxStringLength> data{};
        size_t length{ 0 };
    };

    namespace detail {
        AUTOCRYPT_INLINE constexpr uint8_t RotateLeft8(uint8_t x, unsigned int n) noexcept;
        AUTOCRYPT_INLINE constexpr uint8_t EnhancedMagicHash(uint8_t x) noexcept;
        AUTOCRYPT_INLINE constexpr uint8_t AdvancedBitScramble(uint8_t x) noexcept;
        AUTOCRYPT_INLINE constexpr uint32_t MbaObfuscate(uint32_t x) noexcept;

        AUTOCRYPT_INLINE constexpr uint32_t Hash(const char* str, size_t n);

         constexpr char RandomSymbol(uint32_t hash, int index);

        template<size_t N>
        AUTOCRYPT_INLINE constexpr std::array<char, N> GenerateRandomKey(const char* file, int line)
        {
            std::array<char, N> key{};
            uint32_t hash = Hash(file, __builtin_strlen(file)) ^ line;
            for (size_t i = 0; i < N; ++i) {
                key[i] = RandomSymbol(hash, i);
            }
            return key;
        }

    }

    AUTOCRYPT_INLINE constexpr ComplexDFA GenerateComplexDFA(std::string_view key) noexcept;
    AUTOCRYPT_INLINE constexpr EncryptedData EncryptString(std::string_view input, const ComplexDFA& dfa) noexcept;
    AUTOCRYPT_INLINE std::array<char, kMaxStringLength> DecryptString(const EncryptedData& input, const ComplexDFA& dfa) noexcept;

} // namespace autocrypt

// @fixme: lambda is not needed here?
#define AUTOCRYPT(str) ([]() { \
    constexpr auto key = autocrypt::detail::GenerateRandomKey<16>(__FILE__, __LINE__); \
    constexpr auto dfa = autocrypt::GenerateComplexDFA(std::string_view(key.data(), key.size())); \
    constexpr auto encrypted = autocrypt::EncryptString(str, dfa); \
    static const auto decrypted = autocrypt::DecryptString(encrypted, dfa); \
    return std::string_view(decrypted.data(), encrypted.length); \
})()

#include "autocrypt.inl"