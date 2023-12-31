import os #Импорт взаимодействия с системой и файлами системы
import tkinter as tk #Импорт графического интерфейса
import logging #Импорт логов
import sqlite3 #Импорт встроенного субд
from datetime import datetime #Импорт текущего системного времени
from sqlite3 import Binary
from tkinter import filedialog, messagebox, simpledialog #Импорт взаимодействия с директориями и выбор директории
from Crypto.PublicKey import RSA #Импорт алгоритмов RSA и AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP



class FileEncryptorApp:
    def __init__(self, root): #Инициализация приложения, создание кнопок, привязка обработчиков событий к кнопкам
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

        self.button_hint = tk.Button(root, text="Подсказка", command=self.show_hint,
                                     font=("Helvetica", 12), bg="#FFA500", fg="white", padx=20, pady=10)
        self.button_hint.pack(pady=10)

        self.button_exit = tk.Button(root, text="Выход", command=root.destroy, #Выход из приложения
                                     font=("Helvetica", 12), bg="#6C757D", fg="white", padx=20, pady=10)
        self.button_exit.pack(pady=10)


    def generate_keys(self):#Функция генерации ключей
        password = self.get_password() #Запрос пароля для шифрования
        try:
            generate_priv_pub_key(password)
            self.save_password_to_db(password)  # Сохранение пароля в базу данных
            self.show_message("Ключи сгенерированы.") #В случае успешной генерации ключей выйдет эта надпись, в ином случае, ошибка
        except Exception as e:
            self.show_message(f"Ошибка при генерации ключей: {str(e)}")

    def save_password_to_db(self, password, private_key = open("private.pem").read(), public_key = open("public.pem").read()):
        conn = sqlite3.connect('hints.db') #Установка соединения с базой данных SQLite
        cursor = conn.cursor() #Создание курсора для выполнения операций в базе данных
        cursor.execute("""INSERT INTO hints (generated_password, private_key, public_key) VALUES (?, ?, ?)""",
                       (password, private_key, public_key))# Выполнение SQL-запроса INSERT OR REPLACE для добавления или замены записи
        conn.commit()# Подтверждение всех изменений в базе данных
        conn.close()# Закрытие соединения с базой данных

    def show_hint(self):
        entered_password = simpledialog.askstring("Password", "Введите пароль для просмотра подсказки:", show='*') #Запрос ввода пароля для просмотра подсказки

        if entered_password == "IITU":  # Проверка введенного пароля
            conn = sqlite3.connect('hints.db') #Установка соединения с базой данных SQLite
            cursor = conn.cursor()#Создание курсора для выполнения операций в базе данных
            record = cursor.execute("SELECT * FROM hints ORDER BY record_number DESC LIMIT 1") #Получениеи записи по номеру
            record = cursor.fetchone() #Получение первой найденной записи
            conn.close() #Закрытие соединения с базой данных

            if record: #Проверка наличия записи для вывода подсказки
                hint_message = f"Подсказка: Последний пароль для ключей: {record[1]}"#Формирование текста подсказки на основе найденной записи
                self.show_message(hint_message)#Отображение сообщения с подсказкой
            else:
                self.show_message("Подсказки нет.")#Отображение сообщения о отсутствии подсказки
        else:
            self.show_message("Неверный пароль для просмотра подсказки.")#Отображение сообщения о неверном пароле для просмотра подсказки
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


def generate_priv_pub_key(password=None, self=None): #Функция генерации ключа
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


            #Логирование информации о зашифрованном файле
            encrypted_file_path = os.path.join(os.path.dirname(dest), encrypted_file_name) #Создание пути к зашифрованному файлу путем объединения директории и имени зашифрованного файла
            logging.info(f"Файл {dest} зашифрован в {datetime.now()} и сохранен как {encrypted_file_path}") #Запись информации в лог о зашифрованном файле: имя исходного файла, время шифрования и путь к зашифрованному файлу
        else:
            print('\n[+] Нет публичного ключа для шифрования. Сгенерируйте ключи.')
    except Exception as e:
        raise Exception(f"Ошибка при шифровании файла {dest}: {str(e)}")



def decrypt(dest): #Функция дешифровки
    try:
        if os.path.isfile("private.pem"):#Проверка существования файла с закрытым ключом
            password = get_password()#Запрос пароля для расшифровки
            priv_key_rsa = RSA.import_key(open("private.pem").read(), passphrase=password)#Используя пароль импортируем ключ rsa
            with open(dest, "rb") as file_in:#Открытие файла с зашифрованными даными в двоичном коде
                enc_session_key, nonce, tag = [file_in.read(x) for x in (priv_key_rsa.size_in_bytes(), 16, 16)]
                # Чтение зашифрованного ключа сеанса, случайного числа инициализации (nonce) и кода аутентификации сообщения (MAC) по отдельности.

            chips_rsa = PKCS1_OAEP.new(priv_key_rsa)#Создание объекта для дешифрования по схеме PKCS1_OAEP
            session_key = chips_rsa.decrypt(enc_session_key)#Дешифровка ключа сеанся с помощью chips_rsa

            chips_aes = AES.new(session_key, AES.MODE_EAX, nonce)#Создается объект для дешифрования файла AES в режиме EAX с ключом сеанса session_key и nonce.
            with open(dest, "rb") as file_in:# Файл dest снова открывается для чтения.
                file_in.seek(priv_key_rsa.size_in_bytes() + 16 + 16)# Пропускаются уже прочитанные данные (зашифрованный ключ сеанса, nonce и MAC).
                chips_text = file_in.read()#Cчитывается оставшаяся часть файла, содержащая зашифрованные данные.

            file_name, _ = os.path.splitext(os.path.basename(dest))#Извлекается имя файла без расширения.
            decrypted_file_name = file_name#Дешифрованный файл сохраняется под оригинальным именем.

            data = chips_aes.decrypt_and_verify(chips_text, tag)#Данные файла дешифруются с помощью chips_aes и одновременно проверяется их целостность с помощью MAC.
            with open(os.path.join(os.path.dirname(dest), decrypted_file_name), "wb") as file_out:#Файл с дешифрованными данными сохраняется в директории исходного файла.
                file_out.write(data)#Дешифрованные данные записываются в файл.
            print(f'{dest} дешифрован')
            os.remove(dest)# Исходный зашифрованный файл удаляется после успешного дешифрования

            #Логирование информации о дешифрованном файле
            decrypted_file_path = os.path.join(os.path.dirname(dest), decrypted_file_name) #Создание пути к расшифрованному файлу путем объединения директории и имени расшифрованного файла
            logging.info(f"Файл {dest} дешифрован в {datetime.now()} и сохранен как {decrypted_file_path}") #Запись информации в лог о расшифрованном файле: имя зашифрованного файла, время дешифрования и путь к расшифрованному файлу
        else:
            print('\n[+] Нет приватного ключа для дешифровки.\nСкопируйте ключ "private.pem" в папку со скриптом!')
    except Exception as e:
        raise Exception(f"Ошибка при дешифровании файла {dest}: {str(e)}")


def get_password():#Функция ввода пароля
    password = simpledialog.askstring("Password", "Введите пароль для защиты закрытого ключа:", show='*')
    return password


def user_change_scan_dir(user_change):#функция обрабатывает пользовательский выбор в приложении для шифрования/дешифрования файлов.
    if user_change == "1":
        generate_priv_pub_key()#Вызов функции для генерации ключей
    elif user_change == "2":#Шифрование директории
        dir_crypt = input('\n[+] Введите директорию для шифрования: ')
        print(" ")
        while not os.path.isdir(dir_crypt):
            dir_crypt = input('\n[-] Нет такой папки\n[+] Введите директорию для шифрования: ')
        for address, dirs, files in os.walk(dir_crypt):#Перебор всех файлов в выбранной директории с помощью os.walk.
            for name in files:
                encrypt(os.path.join(address, name))
        main()
    elif user_change == "3":#Дешифрование директории
        dir_crypt = input('\n[+] Введите директорию для дешифровки: ')
        print(" ")
        while not os.path.isdir(dir_crypt):
            dir_crypt = input('\n[-] Нет такой папки\n[+] Введите директорию для дешифровки: ')
        for address, dirs, files in os.walk(dir_crypt):
            for name in files:
                decrypt(os.path.join(address, name))
        main()
    elif user_change == "4":#Выход из приложения
        exit(0)
    else:
        main()


def main():
    user_change = input('\n[+] Выберите действие:\n\t[1] Генерировать публичный и приватный ключ;\n'
                        '\t[2] Зашифровать файлы;\n\t[3] Дешифровать файлы;\n\t[4] Выход\n\t>>> ')
    user_change_scan_dir(user_change)



if __name__ == "__main__":
    root = tk.Tk()#Включение окна tkinter
    app = FileEncryptorApp(root)
    root.mainloop()#Запуск цикла tkinter которое следит за изменениями пользователя



