import streamlit as st

def main():
    st.title("Encryption Algorithm Selector")
    st.sidebar.title("About")
    st.sidebar.info(
        "This app demonstrates AES, DES, 3DES, and RSA encryption and decryption using Python's cryptography library."
    )

    encryption_type = st.radio(
        "Choose an Encryption Algorithm:",
        ("AES", "DES", "3DES", "RSA")
    )

    if encryption_type == "AES":
        import encryption_modules.aes
        encryption_modules.aes.main()

    elif encryption_type == "DES":
        import encryption_modules.des
        encryption_modules.des.main()

    elif encryption_type == "RSA":
        import encryption_modules.rsa
        encryption_modules.rsa.main()

    elif encryption_type == "3DES":
        import encryption_modules.three_des
        encryption_modules.three_des.main()

if __name__ == "__main__":
    main()
