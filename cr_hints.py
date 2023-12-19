import sqlite3

# Создание базы данных SQLite
conn = sqlite3.connect('hints.db')
cursor = conn.cursor()

# Создание таблицы для хранения записей
cursor.execute('''CREATE TABLE IF NOT EXISTS hints
                (record_number INTEGER PRIMARY KEY AUTOINCREMENT, generated_password TEXT,private_key TEXT,public_key TEXT)''')
conn.commit()
conn.close()

#задаем первую строку в нашем бд для проверки
conn = sqlite3.connect('hints.db') #Устанавливает соединение с базой данных SQLite с именем файла "hints.db".
cursor = conn.cursor() #Создает курсор для выполнения операций с базой данных.
cursor.execute("SELECT * FROM hints WHERE record_number = 1") #Выполняет SQL-запрос для выбора записи с номером 1 из таблицы "hints".
record = cursor.fetchone() #Получает результат запроса и сохраняет его в переменную record. Если запись не найдена, record будет пустым.
if not record:
    cursor.execute("INSERT INTO hints (record_number, generated_password,private_key,public_key) VALUES (1, 'Пароль не задан')") #Вставляет новую запись в таблицу "hints" с номером 1 и значением "Пароль не задан".
    conn.commit() #Фиксирует изменения в базе данных (коммитит транзакцию).
conn.close() #Закрывает соединение с базой данных SQLite "hints.db".






