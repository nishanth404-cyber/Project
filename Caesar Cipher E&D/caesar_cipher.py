def encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():                                          # 97 → starting ASCII value of lowercase letters (a–z)
            base = 65 if char.isupper() else 97                     # 65 → starting ASCII value of uppercase letters (A–Z)  
            result += chr((ord(char) - base + shift) % 26 + base)   # ord(chr)"Converts a letter into its ASCII number(26% => en(x+n)/dn(x-n) mod 26)"
        else:                                                       # chr 'Convert ASCII number back to a character'
            result += char
    return result


def decrypt(cipher_text, shift):
    return encrypt(cipher_text, -shift)


# --------------------------
# Main Program
# --------------------------
print("=== Caesar Cipher Tool ===")
message = input("Enter your message: ")
shift = int(input("Enter shift (key): "))

encrypted = encrypt(message, shift)
print("\n Encrypted Text:", encrypted)

decrypted = decrypt(encrypted, shift)
print(" Decrypted Text:", decrypted)

# example calculation 
# result += chr((ord(char) - base + shift) % 26 + base) 

# INPUT METHOD:
# char = 'C'
# shift = 3
# base = 65

# CALCULATION METHOD
# ord('C') = 67
# 67 - 65 = 2
# 2 + 3 = 5
# 5 % 26 = 5
# 5 + 65 = 70
# chr(70) = 'F'


# RESULT 
# C → F
# 
