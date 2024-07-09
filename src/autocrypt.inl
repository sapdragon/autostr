#include "autocrypt.hpp"
namespace autocrypt {
namespace detail {

AUTOCRYPT_INLINE constexpr uint8_t RotateLeft8(uint8_t x, unsigned int n) noexcept {
    n &= 7;
    return (x << n) | (x >> (8 - n));
}

AUTOCRYPT_INLINE constexpr uint8_t EnhancedMagicHash(uint8_t x) noexcept {
    x ^= 0xAA;
    x = RotateLeft8(x, 3);
    x *= 0x13;
    x ^= 0x55;
    x = RotateLeft8(x, 5);
    x += 0x42;
    x ^= (x >> 3);
    x *= 0x2D;
    return x;
}

AUTOCRYPT_INLINE constexpr uint8_t AdvancedBitScramble(uint8_t x) noexcept {
    x = ((x * 0x0802LU & 0x22110LU) | (x * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16;
    x = static_cast<uint8_t>((x & 0xF0) >> 4 | (x & 0x0F) << 4);
    x ^= 0x39;
    x = (x * 7) ^ (x * 23);
    return x;
}

AUTOCRYPT_INLINE constexpr uint32_t MbaObfuscate(uint32_t x) noexcept {
    x = ((x >> 16) | (x << 16)) + (x ^ 0xAAAAAAAA);
    x = (x ^ 0x55555555) - ((x << 1) & 0xFFFFFFFF);
    x = (x + 0x11111111) ^ ((x >> 2) | (x << 30));
    x = x ^ ((x << 5) & 0xFFFFFFFF) ^ ((x >> 7) | (x << 25));
    return x;
}

constexpr AUTOCRYPT_INLINE uint32_t Hash(const char* str, size_t n)
{
    uint32_t hash = 0x811C9DC5;
    for (size_t i = 0; i < n; ++i) {
        hash ^= static_cast<unsigned char>(str[i]);
        hash *= 0x01000193;
    }
    return hash;
}

constexpr char RandomSymbol(uint32_t hash, int index)
{
    return static_cast<char>((hash ^ (hash >> 16) ^ (index * 0x9E3779B9)) & 0xFF);
}

} // namespace detail

AUTOCRYPT_INLINE constexpr ComplexDFA GenerateComplexDFA(std::string_view key) noexcept {
    ComplexDFA dfa;
    std::array<uint8_t, kNumLayers> key_hash{};
    
    for (size_t i = 0; i < kNumLayers; ++i) {
        key_hash[i] = 0x42 + i;
    }

    for (char c : key) {
        for (size_t layer = 0; layer < kNumLayers; ++layer) {
            key_hash[layer] = detail::EnhancedMagicHash(detail::RotateLeft8(key_hash[layer], 1) ^ static_cast<uint8_t>(c) ^ layer);
        }
    }

    for (size_t layer = 0; layer < kNumLayers; ++layer) {
        for (uint8_t state = 0; state < kNumStates; ++state) {
            for (uint16_t symbol = 0; symbol < kAlphabetSize; ++symbol) {
                uint8_t combined = detail::RotateLeft8(state, 2) ^ detail::RotateLeft8(static_cast<uint8_t>(symbol), 3) ^ key_hash[layer];
                combined = detail::EnhancedMagicHash(combined);
                dfa.transitions[layer][state][symbol] = combined % kNumStates;
            }
            dfa.output[layer][state] = detail::AdvancedBitScramble(detail::EnhancedMagicHash(detail::RotateLeft8(key_hash[layer], state)));
        }
        dfa.initial_state[layer] = key_hash[layer] % kNumStates;
    }

    return dfa;
}

AUTOCRYPT_INLINE constexpr EncryptedData EncryptString(std::string_view input, const ComplexDFA& dfa) noexcept {
    EncryptedData result;
    std::array<uint8_t, kNumLayers> state;
    
    for (size_t i = 0; i < kNumLayers; ++i) {
        state[i] = dfa.initial_state[i];
    }
    
    uint32_t counter = 0;

    for (size_t i = 0; i < input.length() && i < kMaxStringLength; ++i) {
        uint8_t symbol = static_cast<uint8_t>(input[i]);
        symbol ^= detail::AdvancedBitScramble(counter & 0xFF);
        for (size_t layer = 0; layer < kNumLayers; ++layer) {
            symbol ^= dfa.output[layer][state[layer]];
            state[layer] = dfa.transitions[layer][state[layer]][symbol];
        }
        result.data[i] = symbol;
        counter = detail::MbaObfuscate(counter) + 17;
    }
    result.length = std::min(input.length(), kMaxStringLength);

    return result;
}

AUTOCRYPT_INLINE std::array<char, kMaxStringLength> DecryptString(const EncryptedData& input, const ComplexDFA& dfa) noexcept {
    std::array<char, kMaxStringLength> result{};
    std::array<uint8_t, kNumLayers> state;
    
    for (size_t i = 0; i < kNumLayers; ++i) {
        state[i] = dfa.initial_state[i];
    }
    
    uint32_t counter = 0;

    for (size_t i = 0; i < input.length; ++i) {
        uint8_t symbol = input.data[i];
        for (int layer = kNumLayers - 1; layer >= 0; --layer) {
            uint8_t prev_state = state[layer];
            state[layer] = dfa.transitions[layer][state[layer]][symbol];
            symbol ^= dfa.output[layer][prev_state];
        }
        symbol ^= detail::AdvancedBitScramble(counter & 0xFF);
        result[i] = static_cast<char>(symbol);
        counter = detail::MbaObfuscate(counter) + 17;
    }

    if (input.length < kMaxStringLength) {
        result[input.length] = '\0';
    }

    return result;
}

} // namespace autocrypt