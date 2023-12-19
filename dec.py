Эрик, [16.12.2023 16:24]
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

class FileEncryptorApp:
    def init(self, root):
        self.root = root
        self.root.title("File Encryptor")

        self.label = tk.Label(root, text="Выберите действие:")
        self.label.pack()

        self.button_generate_keys = tk.Button(root, text="Генерировать ключи", command=self.generate_keys)
        self.button_generate_keys.pack()

        self.button_encrypt = tk.Button(root, text="Зашифровать файлы", command=self.encrypt_files)
        self.button_encrypt.pack()

        self.button_decrypt = tk.Button(root, text="Дешифровать файлы", command=self.decrypt_files)
        self.button_decrypt.pack()

        self.button_exit = tk.Button(root, text="Выход", command=root.destroy)
        self.button_exit.pack()

    def generate_keys(self):
        generate_priv_pub_key()
        self.show_message("Ключи сгенерированы.")

    def encrypt_files(self):
        dir_crypt = self.ask_directory("Выберите директорию для шифрования:")
        if dir_crypt:
            for address, dirs, files in os.walk(dir_crypt):
                for name in files:
                    encrypt(os.path.join(address, name))
            self.show_message("Файлы зашифрованы.")

    def decrypt_files(self):
        dir_crypt = self.ask_directory("Выберите директорию для дешифровки:")
        if dir_crypt:
            for address, dirs, files in os.walk(dir_crypt):
                for name in files:
                    decrypt(os.path.join(address, name))
            self.show_message("Файлы дешифрованы.")

    def ask_directory(self, message):
        dir_crypt = filedialog.askdirectory(title=message)
        return dir_crypt

    def show_message(self, message):
        messagebox.showinfo("File Encryptor", message)

def generate_priv_pub_key():
    key = RSA.generate(2048)
    with open('private.pem', 'wb') as priv:
        priv.write(key.export_key())
    print('\n[+] Приватный ключ "private.pem" сохранен')

    with open('public.pem', 'wb') as pub:
        pub.write(key.publickey().export_key())
    print('[+] Публичный ключ "public.pem" сохранен')



def encrypt(dest):
    with open(dest, 'rb') as enc_file:
        data_enc = enc_file.read()

    if os.path.isfile('public.pem'):
        public_rsa = RSA.import_key(open('public.pem').read())
        session_key = get_random_bytes(16)

        # шифруем сессионный ключ открытым ключом RSA
        chips_rsa = PKCS1_OAEP.new(public_rsa)
        enc_session_key = chips_rsa.encrypt(session_key)

        # шифруем файл с сессионным ключом алгоритм AES
        chips_aes = AES.new(session_key, AES.MODE_EAX)
        chips_text, tag = chips_aes.encrypt_and_digest(data_enc)

        with open(f'{dest}.bin', 'wb') as file_out:
            for x in (enc_session_key, chips_aes.nonce, tag, chips_text):
                file_out.write(x)
        print(f'{dest} зашифрован')
        os.remove(dest)
    else:
        print('\n[+] Нет публичного ключа для шифрования. Сгенерируйте ключи.')
        main()
        return


def decrypt(dest):
    if os.path.isfile("private.pem"):
        priv_key_rsa = RSA.import_key(open("private.pem").read())
        with open(dest, "rb") as file_in:
            enc_session_key, nonce, tag, chips_text = [file_in.read(x) for x in (priv_key_rsa.size_in_bytes(), 16, 16, -1)]

        # расшифровка сессионного ключа закрытым ключом RSA
        chips_rsa = PKCS1_OAEP.new(priv_key_rsa)
        session_key = chips_rsa.decrypt(enc_session_key)

        # расшифровка данных сессионным ключом алгоритм AES
        chips_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = chips_aes.decrypt_and_verify(chips_text, tag)

Эрик, [16.12.2023 16:24]
with open(dest[:-4], "wb") as file_out:
            file_out.write(data)
        print(f'{dest} дешифрован')
        os.remove(dest)
    else:
        print('\n[+] Нет приватного ключа для дешифровки.\nСкопируйте ключ "private.pem" в папку со скриптом!')
        main()
        return


def user_change_scan_dir(user_change):
    if user_change == "1":
        generate_priv_pub_key()
    elif user_change == "2":
        dir_crypt = input('\n[+] Введите директорию для шифрования: ')
        print(" ")
        while not os.path.isdir(dir_crypt):
            dir_crypt = input('\n[-] Нет такой папки\n[+] Введите директорию для шифрования: ')
        for address, dirs, files in os.walk(dir_crypt):
            for name in files:
                encrypt(os.path.join(address, name))
        main()
        return
    elif user_change == "3":
        dir_crypt = input('\n[+] Введите директорию для дешифровки: ')
        print(" ")
        while not os.path.isdir(dir_crypt):
            dir_crypt = input('\n[-] Нет такой папки\n[+] Введите директорию для дешифровки: ')
        for address, dirs, files in os.walk(dir_crypt):
            for name in files:
                decrypt(os.path.join(address, name))
        main()
        return
    elif user_change == "4":
        exit(0)
    else:
        main()
        return


def main():
    user_change = input('\n[+] Выберите действие:\n\t[1] Генерировать публичный и приватный ключ;\n'
                        '\t[2] Зашифровать файлы;\n\t[3] Дешифровать файлы;\n\t[4] Выход\n\t>>> ')
    user_change_scan_dir(user_change)


if name == "main":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()