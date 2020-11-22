from cryptography.hazmat.primitives.asymmetric import rsa    
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

#Sender Key generations
sender_private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)

sender_public_key = sender_private_key.public_key()
pem = sender_public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo )

with open('senderPublicKey.pem','wb') as f:
  f.write(pem);

#Receiver Key generations
receiver_private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)

receiver_public_key = receiver_private_key.public_key()
pem = receiver_public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo )

with open('receiverPublicKey.pem','wb') as f:
  f.write(pem);

#message by sender
message = bytes(input("Enter the text to be encrypted: "), 'utf-8')

#Signing message by sender
signature = sender_private_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

with open('signature','wb') as f:
  f.write(signature);

print("\nThe Signature is -\n", signature.hex())

#Encrypting message by sender
with open("receiverPublicKey.pem", "rb") as key_file:
  receiver_public_key = serialization.load_pem_public_key(key_file.read())

ciphertext = receiver_public_key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None))

print("\nThe ciphertext is -\n", ciphertext.hex())

with open('ciphertext','wb') as f:
  f.write(ciphertext);

#Decrypting message by receiver
with open('ciphertext','rb') as f:
  ciphertext = f.read();

plaintext = receiver_private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),label=None))

print("\n\nDecrypted text is :",str(plaintext))


#Verifying signature by receiver
with open('signature','rb') as f:
  signature = f.read();

try:
  sender_public_key.verify(signature,message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
  print("\n\nSignature verified!")

except:
  print("\n\nSignature not verified!")