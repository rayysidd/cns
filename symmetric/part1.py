import random
import string
import numpy as np


# ------------------------
# Caesar Cipher
# ------------------------
def caesar_encrypt(text, key):
   result = ""
   for ch in text.upper():
       if ch.isalpha():
           result += chr((ord(ch) - 65 + key) % 26 + 65)
       else:
           result += ch
   return result


def caesar_decrypt(cipher, key):
   return caesar_encrypt(cipher, -key)


# ------------------------
# Monoalphabetic Cipher
# ------------------------
def generate_mono_key():
   letters = list(string.ascii_uppercase)
   shuffled = letters[:]
   random.shuffle(shuffled)
   return dict(zip(letters, shuffled)), dict(zip(shuffled, letters))


def mono_encrypt(text, keymap):
   return "".join(keymap.get(ch, ch) for ch in text.upper())

def mono_decrypt(cipher, revmap):
   return "".join(revmap.get(ch, ch) for ch in cipher.upper())


# ------------------------
# Playfair Cipher
# ------------------------
def generate_playfair_matrix(key):
   key = "".join(dict.fromkeys(key.upper().replace("J", "I") + string.ascii_uppercase.replace("J","")))
   matrix = [key[i:i+5] for i in range(0, 25, 5)]
   return matrix


def playfair_encrypt_pair(a, b, matrix):
   if a == b: b = "X"
   for r in range(5):
       for c in range(5):
           if matrix[r][c] == a:
               ra, ca = r, c
           if matrix[r][c] == b:
               rb, cb = r, c
   if ra == rb:
       return matrix[ra][(ca+1)%5] + matrix[rb][(cb+1)%5]
   elif ca == cb:
       return matrix[(ra+1)%5][ca] + matrix[(rb+1)%5][cb]
   else:
       return matrix[ra][cb] + matrix[rb][ca]


def playfair_encrypt(text, key):
   matrix = generate_playfair_matrix(key)
   text = text.upper().replace("J","I")
   pairs = []
   i = 0
   while i < len(text):
       a = text[i]
       b = text[i+1] if i+1 < len(text) else "X"
       if a == b:
           pairs.append((a,"X"))
           i += 1
       else:
           pairs.append((a,b))
           i += 2
   return "".join(playfair_encrypt_pair(a,b,matrix) for a,b in pairs)


# ------------------------
# Hill Cipher
# ------------------------
def hill_encrypt(text, key_matrix):
   text = text.upper().replace(" ", "")
   while len(text) % len(key_matrix) != 0:
       text += "X"
   numbers = [ord(c)-65 for c in text]
   result = ""
   n = len(key_matrix)
   for i in range(0, len(numbers), n):
       block = np.array(numbers[i:i+n])
       enc = np.dot(key_matrix, block) % 26
       result += "".join(chr(num+65) for num in enc)
   return result


def mod_inverse_matrix(matrix, mod=26):
   det = int(round(np.linalg.det(matrix)))
   det_inv = pow(det % mod, -1, mod)
   matrix_mod = np.round(det * np.linalg.inv(matrix)).astype(int) % mod
   return (det_inv * matrix_mod) % mod


def hill_decrypt(cipher, key_matrix):
   inv_matrix = mod_inverse_matrix(key_matrix, 26)
   numbers = [ord(c)-65 for c in cipher]
   result = ""
   n = len(key_matrix)
   for i in range(0, len(numbers), n):
       block = np.array(numbers[i:i+n])
       dec = np.dot(inv_matrix, block) % 26
       result += "".join(chr(num+65) for num in dec)
   return result


# ------------------------
# Vigenere (Polyalphabetic)
# ------------------------
def vigenere_encrypt(text, key):
   text, key = text.upper(), key.upper()
   result = ""
   for i, ch in enumerate(text):
       if ch.isalpha():
           shift = ord(key[i % len(key)]) - 65
           result += chr((ord(ch)-65+shift)%26 + 65)
       else:
           result += ch
   return result


def vigenere_decrypt(cipher, key):
   text, key = cipher.upper(), key.upper()
   result = ""
   for i, ch in enumerate(text):
       if ch.isalpha():
           shift = ord(key[i % len(key)]) - 65
           result += chr((ord(ch)-65-shift)%26 + 65)
       else:
           result += ch
   return result




# ------------------------
# DEMO
# ------------------------
if __name__ == "__main__":
   print("=== Part 1: Substitution Techniques ===")


   # Caesar
   msg = "RayyanSiddiqui"
   c_key = 3
   caes_enc = caesar_encrypt(msg, c_key)
   print(f"Caesar: {msg} -> {caes_enc} -> {caesar_decrypt(caes_enc, c_key)}\n")


   # Monoalphabetic
   keymap, revmap = generate_mono_key()
   mono_enc = mono_encrypt(msg, keymap)
   print(f"Monoalphabetic: {msg} -> {mono_enc} -> {mono_decrypt(mono_enc, revmap)}\n")


   # Playfair
   pf_key = "MONARCHY"
   pf_enc = playfair_encrypt(msg, pf_key)
   print(f"Playfair: {msg} -> {pf_enc}\n")


   # Hill
   hill_key = np.array([[3,3],[2,5]])  # example invertible matrix
   hill_enc = hill_encrypt(msg, hill_key)
   print(f"Hill: {msg} -> {hill_enc} -> {hill_decrypt(hill_enc, hill_key)}\n")


   # Vigenere
   v_key = "KEY"
   vig_enc = vigenere_encrypt(msg, v_key)
   print(f"Vigenere: {msg} -> {vig_enc} -> {vigenere_decrypt(vig_enc, v_key)}\n")



