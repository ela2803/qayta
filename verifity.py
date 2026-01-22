# rsa_verify.py

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def verify_message(message: str, signature_hex: str, public_key_path="public.pem"):
    signature = bytes.fromhex(signature_hex)

    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

if __name__ == "__main__":
    msg = input("Xabar: ")
    sig = input("Imzo (HEX): ")

    if verify_message(msg, sig):
        print("Natija: ✔️ IMZO TO‘G‘RI")759d0b03d703012cd489cd29af37a547d12d73b8da26834aff9cd2e76c11c3cb216c19b314ffce3be75beb65488605753d7d9054f3ed5242f64881175c460fe7ef421535e1920ea55c9ef599b34fbfc5dcb8681203bb3cf3257baf68fb6c01cb101a18cd612eefa62af0255063418667bc5bdb0305dd03878bce570fce00eb6b1d41c073c10431e55df428410317801618e7804729f41ac3b48555490487c45abe7cf97fface8ef33cbe424b6b850d68b13f59c8789c5226ada397444070bd82b7cc465f0c6bef4c62a94e37ae18b266210bea1fed168d87d72b026139634694ffdfa1f25205640cd0468da368544ad106e783e7fc1d26ec87b4e0cebfb43483  
    else:
        print("Natija: ✘ IMZO NOTO‘G‘RI")