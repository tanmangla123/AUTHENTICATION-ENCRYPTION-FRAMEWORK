from Crypto.PublicKey import RSA

def generate_keys():
    key = RSA.generate(2048)

    with open("private.pem", "wb") as prv_file:
        prv_file.write(key.export_key())

    with open("public.pem", "wb") as pub_file:
        pub_file.write(key.publickey().export_key())

    print("Keys generated: private.pem, public.pem")

if __name__ == "__main__":
    generate_keys()
