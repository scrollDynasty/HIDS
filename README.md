# 🛡️ HIDS - Система обнаружения вторжений на хосте с Telegram оповещениями

<div align="center">
  
![Версия](https://img.shields.io/badge/Версия-2.0.0-brightgreen.svg)
![Лицензия: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![C++](https://img.shields.io/badge/C%2B%2B-17-blue.svg)
![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![OpenSSL](https://img.shields.io/badge/OpenSSL-3.0-blue.svg)
![Telegram](https://img.shields.io/badge/Telegram-Bot_API-0088cc.svg)
![Платформа](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)

</div>

Легковесная и мощная система обнаружения вторжений на хосте (HIDS) с интеграцией Telegram для мгновенных оповещений и управления. Написана на C++ и Python с фокусом на производительность, масштабируемость и низкое потребление ресурсов.

## ✨ Возможности

### 🔎 Мониторинг безопасности
- Анализ системных журналов в реальном времени
- Обнаружение попыток брутфорса и неудачных аутентификаций
- Отслеживание успешных входов и выходов из системы
- Мониторинг сетевых соединений и подозрительной активности

### 🔐 Контроль целостности файлов
- Проверка критичных конфигурационных файлов
- SHA-256 хеширование для обнаружения модификаций
- Мгновенные оповещения при изменении конфигурации

### 👀 Анализ поведения
- Выявление подозрительных шаблонов использования
- Обнаружение привилегированных действий
- Анализ аномального времени и источников подключений

### 🤖 Telegram-бот для управления
- Мгновенные оповещения о вторжениях через Telegram
- Управление блокировками подозрительных IP-адресов
- Просмотр системной информации и логов
- Интерактивный интерфейс с кнопками и командами
- Защита с помощью авторизации пользователей

### 🚨 Гибкая система оповещений
- Настраиваемые триггеры для разных типов угроз
- Множественные каналы оповещений (Telegram, файл, syslog)
- Уровни приоритета для фильтрации событий

### 🔒 Активная защита
- Автоматическая блокировка подозрительных IP через iptables
- Управление блокировками через Telegram-бот
- Выполнение пользовательских скриптов при обнаружении вторжений
- Подробное журналирование инцидентов для последующего анализа

## 🚀 Начало работы

### Требования

- Linux-система (Ubuntu, Debian, CentOS, Fedora и т.д.)
- C++17-совместимый компилятор
- Python 3.8+
- OpenSSL
- Библиотеки для сборки (build-essential, libssl-dev)
- Токен Telegram-бота (получается у @BotFather)

### Установка

```bash
# Клонируйте репозиторий
git clone https://github.com/scrollDynasty/HIDS.git
cd HIDS

# Настройка и установка зависимостей
make setup

# Соберите проект
make build

# Настройте параметры Telegram-бота
nano hids_bot/.env

# Пример содержимого .env файла:
# BOT_TOKEN=токен_вашего_бота
# ADMIN_CHAT_ID=ваш_chat_id
# AUTHORIZED_USERS=id1,id2,id3
# HIDS_SOCKET=/var/run/hids/alert.sock
```

### Запуск

```bash
# Создаем директорию для сокета
sudo mkdir -p /var/run/hids
sudo chmod 777 /var/run/hids

# Запуск основной системы HIDS (в одном терминале)
sudo ./bin/hids

# Запуск Telegram-бота (в другом терминале)
make bot
```

### Запуск как системных служб

```bash
# Создание systemd-сервисов
sudo nano /etc/systemd/system/hids.service
sudo nano /etc/systemd/system/hids-bot.service

# Перезагрузка и включение служб
sudo systemctl daemon-reload
sudo systemctl enable hids.service hids-bot.service
sudo systemctl start hids.service hids-bot.service
```

## 📱 Команды Telegram-бота

Бот поддерживает следующие команды:

- `/start` - Начать работу с ботом
- `/help` - Показать справку по командам
- `/alerts` - Показать последние уведомления
- `/alert_detail [IP]` - Детальная информация об IP
- `/system` - Информация о системе
- `/services` - Статус важных сервисов
- `/logs` - Последние записи в журнале
- `/network` - Сетевые соединения

## ⚙️ Конфигурация

### Основная система HIDS

Система настраивается через файл конфигурации, расположенный по умолчанию в `/etc/hids/config.json`. Пример конфигурации:

```ini
# Настройки обнаружения брутфорс атак
bruteforce_threshold=5
bruteforce_window=300  # в секундах

# Настройки проверки целостности файлов
file_check_interval=300  # в секундах
monitored_files=/etc/ssh/sshd_config,/etc/pam.d/sshd

# Настройки анализа поведения
active_time_start=8  # 8:00
active_time_end=20   # 20:00
```

### Telegram-бот

Настройки Telegram-бота хранятся в файле `.env` в директории `hids_bot`:

```
# Токен бота Telegram
BOT_TOKEN=токен_вашего_бота_здесь

# ID чата администратора
ADMIN_CHAT_ID=ваш_chat_id_здесь

# Разрешенные пользователи (через запятую)
AUTHORIZED_USERS=id1,id2,id3

# Путь к сокету HIDS
HIDS_SOCKET=/var/run/hids/alert.sock
```

## 📊 Архитектура

HIDS использует модульную архитектуру, что позволяет легко расширять функциональность:

```
HIDS
├── Ядро C++ (обнаружение и защита)
│   ├── Модуль мониторинга логов
│   ├── Модуль контроля целостности
│   ├── Модуль анализа поведения
│   └── Система оповещений через сокет
└── Telegram-бот (Python)
    ├── Обработка уведомлений от HIDS
    ├── Интерфейс управления
    ├── База данных инцидентов
    └── Выполнение системных команд
```

## 🔧 Тестирование системы

Для тестирования отправки уведомлений можно использовать скрипт:

```bash
# Отправка тестового уведомления
python test_hids_alert.py --ip 192.168.1.100 --reason "Тестовое уведомление"
```

## 📝 Журналирование и мониторинг

HIDS ведет подробные журналы всех обнаруженных инцидентов:

- **Telegram-оповещения**: Моментальные уведомления о инцидентах
- **База данных**: Хранение истории инцидентов
- **Журнал работы**: Записывает действия системы и бота
- **Интеграция с syslog**: Отправляет критические события в системный журнал

## 🛠️ Вклад в проект

Мы приветствуем вклад в проект! Вот как вы можете помочь:

1. **Форкните репозиторий**
2. **Создайте ветку для фичи**: `git checkout -b feature/amazing-feature`
3. **Закоммитьте изменения**: `git commit -m 'Добавлена новая функция'`
4. **Отправьте изменения**: `git push origin feature/amazing-feature`
5. **Откройте Pull Request**

## 📄 Лицензия

Этот проект распространяется под лицензией MIT. См. файл [LICENSE](LICENSE) для получения дополнительной информации.

## 🔗 Полезные ссылки

- [Документация](https://github.com/your-username/HIDS/wiki)
- [Отслеживание проблем](https://github.com/your-username/HIDS/issues)
- [Канал в Telegram](https://t.me/hids_community)

## 🙏 Благодарности

- [aiogram](https://github.com/aiogram/aiogram) за мощный API для Telegram-ботов
- [OpenSSL](https://www.openssl.org/) за надежные криптографические функции
- Сообществу разработчиков безопасности за ценные идеи и вклад
