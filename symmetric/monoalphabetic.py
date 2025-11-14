from collections import Counter

def mono_freq_attack(ciphertext):
    text = ''.join([c.upper() for c in ciphertext if c.isalpha()])
    freq = Counter(text)
    print("\n--- Monoalphabetic Cipher Frequency ---")
    print("Cipher frequencies:", freq.most_common())

# Example ciphertext
cipher = "ZJBBINZQFJM"   #MESSAGE ENCRYPTED: "HELLOSHIVEN"
mono_freq_attack(cipher)
