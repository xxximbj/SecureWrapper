# SecureWrapper
Данная программа представляет собой защитный shell-wrapper, предназначенный для контроля и ограничения интерактивных команд в Linux-среде.
Запуск программы:
1. echo /home/kali/secure_wrapper.py | sudo tee -a /etc/shells
2. chmod 755 /home/kali/secure_wrapper.py
3. chsh -s /home/kali/secure_wrapper.py
4. Перезагрузка
5. Открываем терминал и сразу открывается оболочка
