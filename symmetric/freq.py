import matplotlib.pyplot as plt
from collections import Counter
import string

def get_letter_frequencies(text):
    text = text.upper()
    text = ''.join(filter(str.isalpha, text))
    counter = Counter(text)
    total = sum(counter.values())
    frequencies = {letter: (counter.get(letter, 0) / total) * 100 for letter in string.ascii_uppercase}
    return frequencies


plaintext = "RAYYANSIDDIQUI"
ciphertexts = [
    "UDBBDQVLGGLTXL",
    "YRSSRXBCMMCOVC",
    "MRBWBNAQKBBKLWSA",
    "ZIOMNNAYSVUSGC",
    "BEWIELCMBNMOEM"
]


combined_ciphertext = ' '.join(ciphertexts)


plain_freq = get_letter_frequencies(plaintext)
cipher_freq = get_letter_frequencies(combined_ciphertext)


letters = list(string.ascii_uppercase)
plain_values = [plain_freq[letter] for letter in letters]
cipher_values = [cipher_freq[letter] for letter in letters]


plt.figure(figsize=(14, 6))

plt.subplot(1, 2, 1)
plt.bar(letters, plain_values, color='green')
plt.title("Letter Frequency - Plaintext")
plt.xlabel("Letters")
plt.ylabel("Frequency (%)")
plt.ylim(0, max(max(plain_values), max(cipher_values)) + 5)

plt.subplot(1, 2, 2)
plt.bar(letters, cipher_values, color='orange')
plt.title("Letter Frequency - Ciphertexts")
plt.xlabel("Letters")
plt.ylabel("Frequency (%)")
plt.ylim(0, max(max(plain_values), max(cipher_values)) + 5)

plt.tight_layout()
plt.show()