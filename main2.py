import os #Импорт взаимодействия с системой и файлами системы
import tkinter as tk #Импорт графического интерфейса
import logging #Импорт логов
from datetime import datetime #Импорт текущего системного времени
from tkinter import filedialog, messagebox, simpledialog #Импорт взаимодействия с директориями и выбор директории
from Crypto.PublicKey import RSA #Импорт алгоритмов RSA и AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

class FileEncryptorApp:
    def __init__(self, root): #Инициализация приложения, моздание кнопок, привязка обработчиков событий к кнопкам
        self.root = root
        self.root.title("File Encryptor") #Название окна

        self.label = tk.Label(root, text="Выберите действие:", font=("Helvetica", 16)) #Заголовок
        self.label.pack(pady=10)

        self.button_generate_keys = tk.Button(root, text="Генерировать ключи", command=self.generate_keys, #Генерация RSA-ключей для шифрования и дешифрования файлов
                                              font=("Helvetica", 12), bg="#4CAF50", fg="white", padx=20, pady=10)
        self.button_generate_keys.pack(pady=10)

        self.button_encrypt = tk.Button(root, text="Зашифровать файлы", command=self.encrypt_files, #Шифрование всех файлов во всей директории
                                        font=("Helvetica", 12), bg="#007BFF", fg="white", padx=20, pady=10)
        self.button_encrypt.pack(pady=10)

        self.button_decrypt = tk.Button(root, text="Дешифровать файлы", command=self.decrypt_files, #Дешифрование всех файлов во всей директории
                                        font=("Helvetica", 12), bg="#DC3545", fg="white", padx=20, pady=10)
        self.button_decrypt.pack(pady=10)

        self.button_exit = tk.Button(root, text="Выход", command=root.destroy, #Выход из приложения
                                     font=("Helvetica", 12), bg="#6C757D", fg="white", padx=20, pady=10)
        self.button_exit.pack(pady=10)

    def generate_keys(self):#Функция генерации ключей
        password = self.get_password() #Запрос пароля для шифрования
        try:
            generate_priv_pub_key(password)
            self.show_message("Ключи сгенерированы.") #В случае успешной генерации ключей выйдет эта надпись, в ином случае, ошибка
        except Exception as e:
            self.show_message(f"Ошибка при генерации ключей: {str(e)}")

    def encrypt_files(self): #Функция для шифрования файла
        dir_crypt = self.ask_directory("Выберите директорию для шифрования:") #Выбираем директорию для использования в коде
        if dir_crypt:
            try:
                for address, dirs, files in os.walk(dir_crypt): #Цикл проходит по всем файлам в директории
                    for name in files: # Цикл который выполняется для каждолго файла в директории
                        encrypt(os.path.join(address, name)) #Вызывается функция encrypt для шифрования файлов
                self.show_message("Файлы зашифрованы.")
            except Exception as e:
                self.show_message(f"Ошибка при шифровании файлов: {str(e)}")

    def decrypt_files(self):#Функция дешифровки файла
        dir_crypt = self.ask_directory("Выберите директорию для дешифровки:") #Выбираем директорию для использования в коде
        if dir_crypt:
            try:
                for address, dirs, files in os.walk(dir_crypt): #Цикл проходит по всем файлам в директории
                    for name in files: # Цикл который выполняется для каждолго файла в директории
                        decrypt(os.path.join(address, name))#Вызывается функция decrypt для шифрования файлов
                self.show_message("Файлы дешифрованы.")
            except Exception as e:
                self.show_message(f"Ошибка при дешифровании файлов: {str(e)}")

    def ask_directory(self, message):#функция выбора директории
        dir_crypt = filedialog.askdirectory(title=message)
        return dir_crypt

    def show_message(self, message): #Функция вывода сообщений
        messagebox.showinfo("File Encryptor", message)

    def get_password(self): #Функция принятия пароля для дешифровки
        password = simpledialog.askstring("Password", "Введите пароль для защиты закрытого ключа:", show='*')
        return password


def generate_priv_pub_key(password=None): #Функция генерации ключа
    try:
        key = RSA.generate(2048)#Генерация пары ключей, длиной 2048 бит
        with open('private.pem', 'wb') as priv: #Блок кода открывает файл для записи туда ключей
            if password:
                enc_key = key.export_key(passphrase=password, pkcs=8, protection="scryptAndAES128-CBC")#Строка кода шифрует закрытый ключ с помощью алгоритма scryptAndAES128-CBC.
                priv.write(enc_key)#Запись закрытого ключа в файл
            else:
                priv.write(key.export_key())

        print('\n[+] Приватный ключ "private.pem" сохранен') #сообщение о сохранении ключа

        with open('public.pem', 'wb') as pub: #открытие файла для публичного ключа
            pub.write(key.publickey().export_key())#Запись публичного ключа в файл
        print('[+] Публичный ключ "public.pem" сохранен')
    except Exception as e:
        raise Exception(f"Ошибка при генерации ключей: {str(e)}")


LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
LOG_FILE = "file_encryptor.log"

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format=LOG_FORMAT)#Настройка системы логирования

def encrypt(dest):#Получение файла для шифровки в функцию шифрования
    try:
        with open(dest, 'rb') as enc_file:#открытие в двоичном коде и чтение файла а так же присваивание его переменной data_enc
            data_enc = enc_file.read()

        if os.path.isfile('public.pem'): #проверка наличия публичного ключа
            public_rsa = RSA.import_key(open('public.pem').read()) #импорт и сохранение публичного ключа в переменной
            session_key = get_random_bytes(16) #Генерация 16-байтовый случайный ключ и сохранение его в объекте

            chips_rsa = PKCS1_OAEP.new(public_rsa) #Создание объекта для шифрования по схеме PKCS1_OAEP с ключом public_rsa
            enc_session_key = chips_rsa.encrypt(session_key)#шифрование ключа сеанса и сохранение его в объекте enc_session_key

            chips_aes = AES.new(session_key, AES.MODE_EAX) #Создание объекта для шифрования файлов aes в режиме eax с ключом сеанса
            chips_text, tag = chips_aes.encrypt_and_digest(data_enc)#Шифрование содержимого файла с помощью aes и сохранения зашифрованных данных в chips_text

            file_name, _ = os.path.splitext(os.path.basename(dest))#Извлечение имени файла без разширения
            encrypted_file_name = file_name + '.bin' #Добавление bin к имени зашифрованного файла

            with open(os.path.join(os.path.dirname(dest), encrypted_file_name), 'wb') as file_out: #Открытие файла в директории исходного файла
                for x in (enc_session_key, chips_aes.nonce, tag, chips_text):#записывает по порядку зашифрованный ключ сеанса, случайное число инициализации (nonce) для AES, MAC и зашифрованные данные файла в открытый файл.
                    file_out.write(x)
            print(f'{dest} зашифрован')
            os.remove(dest)

            # Логирование информации о зашифрованном файле
            encrypted_file_path = os.path.join(os.path.dirname(dest), encrypted_file_name)
            logging.info(f"Файл {dest} зашифрован в {datetime.now()} и сохранен как {encrypted_file_path}")
        else:
            print('\n[+] Нет публичного ключа для шифрования. Сгенерируйте ключи.')
    except Exception as e:
        raise Exception(f"Ошибка при шифровании файла {dest}: {str(e)}")



def decrypt(dest):
    try:
        if os.path.isfile("private.pem"):
            password = get_password()
            priv_key_rsa = RSA.import_key(open("private.pem").read(), passphrase=password)
            with open(dest, "rb") as file_in:
                enc_session_key, nonce, tag = [file_in.read(x) for x in (priv_key_rsa.size_in_bytes(), 16, 16)]

            chips_rsa = PKCS1_OAEP.new(priv_key_rsa)
            session_key = chips_rsa.decrypt(enc_session_key)

            chips_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            with open(dest, "rb") as file_in:
                file_in.seek(priv_key_rsa.size_in_bytes() + 16 + 16)
                chips_text = file_in.read()

            file_name, _ = os.path.splitext(os.path.basename(dest))
            decrypted_file_name = file_name

            data = chips_aes.decrypt_and_verify(chips_text, tag)
            with open(os.path.join(os.path.dirname(dest), decrypted_file_name), "wb") as file_out:
                file_out.write(data)
            print(f'{dest} дешифрован')
            os.remove(dest)

            decrypted_file_path = os.path.join(os.path.dirname(dest), decrypted_file_name)
            logging.info(f"Файл {dest} дешифрован в {datetime.now()} и сохранен как {decrypted_file_path}")
        else:
            print('\n[+] Нет приватного ключа для дешифровки.\nСкопируйте ключ "private.pem" в папку со скриптом!')
    except Exception as e:
        raise Exception(f"Ошибка при дешифровании файла {dest}: {str(e)}")


def get_password():
    password = simpledialog.askstring("Password", "Введите пароль для защиты закрытого ключа:", show='*')
    return password


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
    elif user_change == "3":
        dir_crypt = input('\n[+] Введите директорию для дешифровки: ')
        print(" ")
        while not os.path.isdir(dir_crypt):
            dir_crypt = input('\n[-] Нет такой папки\n[+] Введите директорию для дешифровки: ')
        for address, dirs, files in os.walk(dir_crypt):
            for name in files:
                decrypt(os.path.join(address, name))
        main()
    elif user_change == "4":
        exit(0)
    else:
        main()


def main():
    user_change = input('\n[+] Выберите действие:\n\t[1] Генерировать публичный и приватный ключ;\n'
                        '\t[2] Зашифровать файлы;\n\t[3] Дешифровать файлы;\n\t[4] Выход\n\t>>> ')
    user_change_scan_dir(user_change)


if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()





