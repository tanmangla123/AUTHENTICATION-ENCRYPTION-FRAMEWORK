from Crypto.PublicKey import RSA
import os

def generate_keys():
    # Create 'keys' directory if it doesn't exist
    if not os.path.exists("keys"):
        os.makedirs("keys")

    key = RSA.generate(2048)

    # Save keys in the 'keys' directory
    with open("keys/private.pem", "wb") as prv_file:
        prv_file.write(key.export_key())

    with open("keys/public.pem", "wb") as pub_file:
        pub_file.write(key.publickey().export_key())

    print("Keys generated in the 'keys' folder: private.pem, public.pem")

if __name__ == "__main__":
    generate_keys()
