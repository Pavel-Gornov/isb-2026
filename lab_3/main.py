from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES


def main(settings: dict[str, str], mode: str, length: int) -> None:
    ...



if __name__ == "__main__":
    import argparse
    import json
    parser = argparse.ArgumentParser()

    parser.add_argument("-s", "--settings", help="Путь до файла с параметрами", default="./settings.json")
    parser.add_argument("-l", "--length", choices=(64, 128, 192), help="Длинна ключа шифрования", default=64)

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
