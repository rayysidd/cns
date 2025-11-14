def caesar_bruteforce(ciphertext):
    print("\n--- Caesar Cipher Brute Force ---")
    for key in range(26):
        translated = ""
        for symbol in ciphertext:
            if symbol.isalpha():
                base = ord('A') if symbol.isupper() else ord('a')
                translated += chr((ord(symbol) - base - key) % 26 + base)
            else:
                translated += symbol
        print(f"Key {key}: {translated}")

cipher = "KHOORVKLYHQ"   #MESSAGE ENCRYPTED:"HELLOSHIVEN"
caesar_bruteforce(cipher)
