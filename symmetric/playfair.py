def playfair_frequency_attack(ciphertext):
    text = ''.join([c.upper() for c in ciphertext if c.isalpha()])
    digrams = [text[i:i+2] for i in range(0, len(text), 2)]
    from collections import Counter
    freq = Counter(digrams)
    print("\n--- Playfair Frequency Analysis ---")
    print("Top ciphertext digrams:")
    for digram, count in freq.most_common(10):
        print(f"{digram}: {count}")

#MESSAGE ENCRYPTED: "HELLOSHIVEN"
cipher = "CFSUBPMPBFXGM"
playfair_frequency_attack(cipher)
