Проект на прикладну криптологію.

Викладач: Трушевський Валерій Миколайович

Робив під Лінукс
Встановлення:

git clone https://github.com/maxyrrr-sh/secure-comm.git

cd secure-comm

make build

Запуск:

bin/secure-comm

Працює в локальній мережі.

Процес обміну сертифікатами:

Кожен користувач генерує пару ключів

Встановлення з'єднання:


Клієнт 1 передає свій публічний ключ Клієнту 2.

Клієнт 2 передає свій публічний ключ Клієнту 1.


За допомогою публічного ключа обидва клієнти генерують спільний симетричний ключ AES для шифрування даних.
