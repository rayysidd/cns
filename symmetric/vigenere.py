def vigenere_decrypt(ciphertext, key):
    result = ""
    key = key.upper()
    ki = 0
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[ki % len(key)]) - ord('A')
            result += chr((ord(ch) - base - shift) % 26 + base)
            ki += 1
        else:
            result += ch
    return result

def vigenere_dictionary_attack(ciphertext, dictionary=["KEY", "SECRET", "HELLO"]):
    print("\n--- Vigenère Dictionary Attack ---")
    for word in dictionary:
        guess = vigenere_decrypt(ciphertext, word)
        print(f"Key '{word}': {guess}")

cipher = "RIJVSQRMTOR"   #MESSAGE ENCRYPTED: "HELLOSHIVEN"
dictionary = ["KEY", "HELLO", "SECRET"]
vigenere_dictionary_attack(cipher, dictionary)
