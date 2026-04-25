from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import colorama
from colorama import Fore, Back, Style
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


def get_symmetric_key(settings: dict[str, str | int | bytes]) -> bytes:
    """Возвращает расшифрованный ключ для симметричного алгоритма системы"""
    encrypted_key = deserialize(settings["symmetric_key"])
    private_key = load_pem_private_key(deserialize(settings["secret_key"]), password=None)

    symmetric_key = private_key.decrypt(encrypted_key,
        padding=OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    return symmetric_key


def generate_keys(settings: dict[str, str | int | bytes]) -> None:
    """Процедура, создающая ключи и сериализующая их"""
    print(Back.GREEN + Style.BRIGHT + f"Создаём симметричный ключ длинной {settings['3des_key_size']} бит.")
    symmetric_key = os.urandom(settings["3des_key_size"] // 8)

    print(Back.GREEN + Style.BRIGHT + f"Создаём публичный и приватный ключ.")
    keys = rsa.generate_private_key(public_exponent=settings["rsa_public_exponent"], key_size=settings["rsa_key_size"])
    private_key = keys
    public_key = keys.public_key()

    serialize(settings["secret_key"],
              private_key.private_bytes(
                  encoding=Encoding.PEM,
                  format=PrivateFormat.TraditionalOpenSSL,
                  encryption_algorithm=NoEncryption())
              )
    print("Приватный ключ сохранён в", Fore.BLUE + f"{os.path.abspath(settings['secret_key'])}")

    serialize(settings["public_key"],
              public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
              )
    print("Публичный ключ сохранён в", Fore.BLUE + f"{os.path.abspath(settings['public_key'])}")
    print(Back.GREEN + Style.BRIGHT + "Шифруем симметричный ключ.")
    encrypted_key = public_key.encrypt(symmetric_key,
        padding=OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    serialize(settings["symmetric_key"], encrypted_key)
    print("Зашифрованный симметричный ключ сохранён в", Fore.BLUE + f"{os.path.abspath(settings['symmetric_key'])}")


def encrypt(settings: dict[str, str | int | bytes]) -> None:
    """Процедура, шифрующая содержимое исходного файла симметричным алгоритмом (3DES)"""
    print(Fore.GREEN + "Получаем ключ.")
    symmetric_key = get_symmetric_key(settings)
    x3des = TripleDES(symmetric_key)
    cipher = Cipher(x3des, mode=modes.CBC(settings["3des_init_vector"]))
    encryptor = cipher.encryptor()

    padder = padding.ANSIX923(x3des.block_size).padder()
    print("Шифруемый файл:", Fore.BLUE + f"{os.path.abspath(settings['initial_file'])}")
    file_data = deserialize(settings["initial_file"])
    padded_data = padder.update(file_data) + padder.finalize()

    print(Fore.GREEN + "Шифруем...")
    enc_file_data = encryptor.update(padded_data) + encryptor.finalize()

    serialize(settings["encrypted_file"], enc_file_data)
    print("Результат сохранён в", Fore.BLUE + f"{os.path.abspath(settings['encrypted_file'])}")


def decrypt(settings: dict[str, str | int | bytes]) -> None:
    """Процедура, дешифрующая зашифрованный с помощью симметричного алгоритма файл"""
    print(Fore.GREEN + "Получаем ключ.")
    symmetric_key = get_symmetric_key(settings)
    x3des = TripleDES(symmetric_key)
    cipher = Cipher(x3des, mode=modes.CBC(settings["3des_init_vector"]))
    decryptor = cipher.decryptor()
    unpadder = padding.ANSIX923(x3des.block_size).unpadder()

    enc_file_data = deserialize(settings["encrypted_file"])
    print("Расшифровываем", Fore.BLUE + f"{os.path.abspath(settings['encrypted_file'])}")
    dec_file_data = decryptor.update(enc_file_data) + decryptor.finalize()
    unpadded_data = unpadder.update(dec_file_data) + unpadder.finalize()

    print(Fore.GREEN + "Расшифрованный текст:")
    print(Style.DIM + unpadded_data.decode('UTF-8'))

    serialize(settings["decrypted_file"], unpadded_data)
    print("Результат сохранён в", Fore.BLUE + f"{os.path.abspath(settings['decrypted_file'])}")


def main(settings: dict[str, str | int | bytes], mode: str) -> None:
    """Точка входа в логику программы"""
    colorama.init(autoreset=True)

    match mode:
        case "gen":
            generate_keys(settings)
        case "enc":
            encrypt(settings)
        case "dec":
            decrypt(settings)


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser()

    parser.add_argument("-s", "--settings", help="Путь до файла с параметрами", default="./settings.json")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-gen', '--generation', action='store_const', const='gen', dest='mode', help='Запускает режим генерации ключей')
    group.add_argument('-enc', '--encryption', action='store_const', const='enc', dest='mode', help='Запускает режим шифрования')
    group.add_argument('-dec', '--decryption', action='store_const', const='dec', dest='mode', help='Запускает режим дешифрования')

    args = parser.parse_args()

    try:
        with open(args.settings, mode="r", encoding="utf-8") as input:
            settings = json.load(input)
        settings.setdefault("rsa_public_exponent", 65537)
        settings.setdefault("rsa_key_size", 2048)
        settings.setdefault("3des_key_size", 64)
        # JSON не поддерживает хранения байтовых объектов. Можно использовать кодировку в base64, но массив чисел выглядит приятнее. 
        settings.setdefault("3des_init_vector", (255, 241, 68, 43, 13, 31, 35, 86))
        settings["3des_init_vector"] = bytes(settings["3des_init_vector"])

        main(settings, args.mode)
    except FileNotFoundError as e:
        print(f"Файл {e.filename} не найден!")
