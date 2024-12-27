import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

def encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext, iv

def decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return plaintext.decode()

def main():
    st.title("AES Encryption and Decryption")
    st.sidebar.title("About")
    st.sidebar.info(
        "This application demonstrates AES encryption and decryption using Python "
        "and the Cryptography library."
    )
    key = st.text_input("Enter the encryption key (16, 24, or 32 bytes):", type="password")
    data = st.text_input("Enter the plaintext:")

    if st.button("Encrypt and Decrypt"):
        if not key:
            st.error("Encryption key is required!")
        elif len(key) not in [16, 24, 32]:
            st.error("Invalid key length. Please use a key with 16, 24, or 32 bytes.")
        elif not data:
            st.error("Plaintext is required!")
        else:
            try:
                key_bytes = key.encode()
                ciphertext, iv = encrypt(data, key_bytes)
                decrypted_text = decrypt(ciphertext, key_bytes, iv)
                st.success("Encryption and Decryption Successful!")
                st.subheader("Results")
                st.write(f"Plaintext: {data}")
                st.write(f"Ciphertext: {ciphertext.hex()}")
                st.write(f"IV: {iv.hex()}")
                st.write(f"Decrypted Text: {decrypted_text}")
            except Exception as e:
                st.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
