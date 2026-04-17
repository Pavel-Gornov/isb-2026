from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
import os


def deserialize(path: str) -> bytes:
    """Функция для считывания (десериализации) данных из файла"""
    with open(path, mode='rb') as file:
        data = file.read()
    return data

def serialize(path: str, data: bytes) -> None:
    """Функция для сериализации данных в файл"""
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.exists(directory):
        os.makedirs(directory)
    with open(path, mode='wb') as file:
        file.write(data)


def generate_keys(settings: dict[str, str], length: int) -> None:
    symmetric_key = os.urandom(length // 8)

    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = keys
    public_key = keys.public_key()

    print(private_key)
    print(public_key)

    serialize(settings["secret_key"], 
              private_key.private_bytes(
                  encoding=Encoding.PEM, 
                  format=PrivateFormat.TraditionalOpenSSL, 
                  encryption_algorithm=NoEncryption())
    )

    serialize(settings["public_key"], 
              public_key.public_bytes(
                  encoding=Encoding.PEM, 
                    format=PublicFormat.SubjectPublicKeyInfo)
    )

    encrypted_key = public_key.encrypt(symmetric_key, 
        padding=padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)
    )

    serialize(settings["symmetric_key"], encrypted_key)



def main(settings: dict[str, str], mode: str, length: int) -> None:
    if mode == "gen":
        generate_keys(settings, length)
    ...



if __name__ == "__main__":
    import argparse
    import json
    parser = argparse.ArgumentParser()

    parser.add_argument("-s", "--settings", help="Путь до файла с параметрами", default="./settings.json")
    parser.add_argument("-l", "--length", choices=("64", "128", "192"), help="Длинна ключа шифрования", default=64)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-gen', '--generation', action='store_true', help='Запускает режим генерации ключей')
    group.add_argument('-enc', '--encryption', action='store_true', help='Запускает режим шифрования')
    group.add_argument('-dec', '--decryption', action='store_true', help='Запускает режим дешифрования')

    args = parser.parse_args()

    try:
        with open(args.settings, mode="r", encoding="utf-8") as input:
            settings = json.load(input)

        if args.generation:
            mode = "gen"
        elif args.encryption:
            mode = "enc"
        else:
            mode = "dec"

        main(settings, mode, int(args.length))
    except FileNotFoundError as e:
        print(f"Файл {e.filename} не найден!")
