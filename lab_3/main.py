from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import os


def create_iv(length: int) -> bytes:
    """
    Вспомогательная функция для создания вектора инициализации нужной длинны.
    Да, это примитивный генератор псевдослучайных чисел. Всё равно лучше, чем записанная константа.
    """
    result = bytes()
    state = 42
    for _ in range(length):
        state = (state * 57 + 19) % 256
        result += state.to_bytes(1)
    return result


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


def get_symmetric_key(settings: dict[str, str]) -> bytes:
    """Возвращает расшифрованный ключ для симметричного алгоритма системы"""
    encrypted_key = deserialize(settings["symmetric_key"])
    private_key = load_pem_private_key(deserialize(settings["secret_key"]), password=None)

    symmetric_key = private_key.decrypt(encrypted_key,
        padding=OAEP(mgf=MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)
    )

    return symmetric_key


def generate_keys(settings: dict[str, str], length: int) -> None:
    """Процедура, создающая ключи и сериализующая их"""
    symmetric_key = os.urandom(length // 8)

    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = keys
    public_key = keys.public_key()

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
        padding=OAEP(mgf=MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)
    )

    serialize(settings["symmetric_key"], encrypted_key)


def encrypt(settings: dict[str, str]) -> None:
    """Процедура, шифрующая содержимое исходного файла симметричным алгоритмом (3DES)"""
    symmetric_key = get_symmetric_key(settings)
    x3des = TripleDES(symmetric_key)
    block_size = x3des.block_size
    cipher = Cipher(x3des, mode=modes.CBC(create_iv(block_size // 8)))
    encryptor = cipher.encryptor()

    padder = padding.ANSIX923(block_size).padder()
    file_data = deserialize(settings["initial_file"])
    padded_data = padder.update(file_data) + padder.finalize()
    
    enc_file_data = encryptor.update(padded_data) + encryptor.finalize()

    serialize(settings["encrypted_file"], enc_file_data)


def decrypt(settings: dict[str, str]) -> None:
    """Процедура, дешифрующая зашифрованный с помощью симметричного алгоритма файл"""
    symmetric_key = get_symmetric_key(settings)
    x3des = TripleDES(symmetric_key)
    block_size = x3des.block_size
    cipher = Cipher(x3des, mode=modes.CBC(create_iv(block_size // 8)))
    decryptor = cipher.decryptor()
    unpadder = padding.ANSIX923(block_size).unpadder()

    enc_file_data = deserialize(settings["encrypted_file"])
    dec_file_data = decryptor.update(enc_file_data) + decryptor.finalize()
    unpadded_data = unpadder.update(dec_file_data) + unpadder.finalize()

    print("Расшифрованный текст:")
    print(unpadded_data.decode('UTF-8'))

    serialize(settings["decrypted_file"], unpadded_data)


def main(settings: dict[str, str], mode: str, length: int) -> None:
    if mode == "gen":
        generate_keys(settings, length)
    elif mode == "enc":
        encrypt(settings)
    elif mode == "dec":
        decrypt(settings)


if __name__ == "__main__":
    import argparse
    import json
    parser = argparse.ArgumentParser()

    parser.add_argument("-s", "--settings", help="Путь до файла с параметрами", default="./settings.json")
    parser.add_argument("-l", "--length", type=int, choices=(64, 128, 192), help="Длинна ключа шифрования", default=64)

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

        main(settings, mode, args.length)
    except FileNotFoundError as e:
        print(f"Файл {e.filename} не найден!")
