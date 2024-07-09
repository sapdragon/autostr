#include <iostream>
#include <string_view>
#include "autocrypt.hpp"

int main() {
    // @note / SapDragon: Default usage
    constexpr std::string_view key = "secret_key";
    constexpr std::string_view plaintext = "Hello, AutoCrypt!";

    constexpr auto dfa = autocrypt::GenerateComplexDFA(key);
    constexpr auto encrypted = autocrypt::EncryptString(plaintext, dfa);

    auto decrypted = autocrypt::DecryptString(encrypted, dfa);

    std::cout << "Original: " << plaintext << std::endl;
    std::cout << "Decrypted: " << decrypted.data() << std::endl;

    // @note / SapDragon: Using AUTOCRYPT macros
    auto runtime_decrypted1 = AUTOCRYPT("First encrypted string");
    auto runtime_decrypted2 = AUTOCRYPT("Second encrypted string");

    std::cout << "Runtime decrypted 1: " << runtime_decrypted1 << std::endl;
    std::cout << "Runtime decrypted 2: " << runtime_decrypted2 << std::endl;
}