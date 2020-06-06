#!/usr/bin/python3

from base64 import b64encode, b64decode;
from Crypto.PublicKey import RSA;
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5;
from Crypto.Cipher import AES;
from Crypto import Random;

pad_str = lambda s: s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size);

def encryptRSA(decrypted_string, public_key = None):

  assert type(decrypted_string) is str;
  recipient_key = RSA.import_key(open("rsa_public.pem").read() if public_key is None else public_key);
  cipher_rsa = PKCS1_v1_5.new(recipient_key);
  data = cipher_rsa.encrypt(decrypted_string.encode());
  encrypted_string = b64encode(data).decode();
  assert type(encrypted_string) is str;
  return encrypted_string;

def decryptRSA(encrypted_string, private_key = None, passphrase = 'test123'):

  assert type(encrypted_string) is str;
  data = b64decode(encrypted_string.encode());
  private_key = RSA.import_key(open("private_rsa_key.bin").read() if private_key is None else private_key, passphrase = passphrase);
  cipher_rsa = PKCS1_v1_5.new(private_key);
  decrypted_string = cipher_rsa.decrypt(data, None).decode();
  assert type(decrypted_string) is str;
  return decrypted_string;

def generateKeypairRSA(passphrase):

  key = RSA.generate(1024);
  encrypted_key = key.exportKey(passphrase = passphrase, pkcs = 8, protection = "scryptAndAES128-CBC");
  with open("private_rsa_key.bin", "wb") as f:
    f.write(encrypted_key);
  with open("rsa_public.pem", "wb") as f:
    f.write(key.publickey().exportKey());
  return encrypted_key, key.publickey().exportKey();

def encryptAES(decrypted_string, key, iv):

  assert type(decrypted_string) is str;
  aes = AES.new(key, AES.MODE_CBC, iv);
  data = aes.encrypt(pad_str(decrypted_string).encode());
  encrypted_string = b64encode(data).decode();
  assert type(encrypted_string) is str;
  return encrypted_string;

def decryptAES(encrypted_string, key, iv):

  assert type(encrypted_string) is str;
  aes = AES.new(key, AES.MODE_CBC, iv);
  data = b64decode(encrypted_string.encode());
  decrypted_string = aes.decrypt(data).decode();
  assert type(decrypted_string) is str;
  return decrypted_string;

def generateAES():

  key = Random.new().read(AES.block_size);
  iv = Random.new().read(AES.block_size);
  return key, iv;

if __name__ == "__main__":

  prik, pubk = generateKeypairRSA("test123");
  en_data = encryptRSA("abc123123", pubk);
  de_data = decryptRSA(en_data, prik, "test123");
  print(de_data);
  key, iv = generateAES();
  en_data = encryptAES("abc123123", key, iv);
  de_data = decryptAES(en_data, key, iv);
  print(de_data);
