import numpy as np

def to_nums(text):
    return [ord(c) - 65 for c in text.upper() if c.isalpha()]

def to_text(nums):
    return ''.join(chr(n + 65) for n in nums)

def hill_encrypt(plaintext, K, n):
    nums = to_nums(plaintext)
    nums = nums[:(len(nums)//n)*n]  # make divisible by n
    P = np.array(nums).reshape(-1, n).T
    C = (K.dot(P)) % 26
    return to_text(C.T.flatten())

def mod_inverse_matrix(matrix, mod=26):
    """Find modular inverse of matrix (integer method)."""
    det = int(round(np.linalg.det(matrix))) % mod
    det_inv = pow(det, -1, mod)  # modular inverse of determinant
    
    # adjugate (cofactor transpose)
    n = matrix.shape[0]
    adj = np.zeros((n, n), dtype=int)
    for r in range(n):
        for c in range(n):
            minor = np.delete(np.delete(matrix, r, axis=0), c, axis=1)
            cofactor = int(round(np.linalg.det(minor)))
            adj[c, r] = ((-1) ** (r + c)) * cofactor
    return (det_inv * adj) % mod

def hill_attack(plaintext, ciphertext, n):
    """Recover Hill cipher key matrix from known plaintext-ciphertext pairs."""
    p_nums = to_nums(plaintext)
    c_nums = to_nums(ciphertext)
    
    # Use only first n blocks to form square matrix
    P = np.array(p_nums[:n*n]).reshape(n, n).T
    C = np.array(c_nums[:n*n]).reshape(n, n).T
    
    # Compute inverse of P modulo 26
    P_inv = mod_inverse_matrix(P, 26)
    
    # Recover key
    K = (C.dot(P_inv)) % 26
    return K

# Example key
K = np.array([[3, 3],
              [2, 5]])

plaintext = "HELLOSHIVEN"  # 10 letters
ciphertext = hill_encrypt(plaintext, K, 2)
print("Plain Test:", plaintext)
print("Ciphertext:", ciphertext)

recovered_K = hill_attack(plaintext, ciphertext, 2)
print("Recovered K:\n", recovered_K)


