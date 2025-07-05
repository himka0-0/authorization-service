# MEDODS Auth Service

Сервис аутентификации пользователей.

---

## 🚀 Быстрый старт

### 1️⃣ Подготовка

Установите:

- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)

Обновите `.env` в корне проекта или используйте дефолтный

---

### 2️⃣ Запуск

Выполните команду:

```
docker-compose -f docker-compose.yml up -d
```

После запуска будут доступны:

- 🌐 API: http://localhost:8080
- 📘 Swagger UI: http://localhost:8081

---

## ⚙️ Основные возможности

✅ Получение access и refresh токенов  
✅ Обновление пары токенов  
✅ Получение GUID текущего пользователя (защищённый эндпоинт)  
✅ Деавторизация пользователя

---

## 🌐 Эндпоинты

| Метод | URL                   | Описание                                     |
|-------|-----------------------|----------------------------------------------|
| GET   | /login/user/{guid}    | Получить access и refresh токены            |
| POST  | /refresh              | Обновить токены                             |
| GET   | /myguid               | Получить GUID текущего пользователя         |
| POST  | /logout               | Деавторизация пользователя                  |

Подробности и примеры ошибок — в Swagger-документации.

---

## 🧪 Тестирование

Запуск тестов:

```
go test ./...
```

---

## 📘 Swagger OpenAPI

Файл OpenAPI находится здесь:

```
/docs/openapi.yaml
```

Можно открыть на https://editor.swagger.io или воспользоваться встроенным Swagger UI:

http://localhost:8081

---

## 📂 Структура проекта

```
.
├── cmd/
│   └── server/
│       └── main.go           # Точка входа приложения
├── internal/
│   ├── api/                  # HTTP хендлеры
│   ├── db/                   # Подключение к базе данных
│   ├── middleware/           # Middleware авторизации
│   ├── model/                # GORM модели
│   ├── repository/           # Работа с БД
│   ├── service/              # Бизнес-логика
│   ├── tokens/               # JWT менеджер
│   └── util/                 # Вспомогательные функции
├── docs/
│   └── openapi.yaml          # OpenAPI спецификация
├── Dockerfile
├── docker-compose.yml
├── .env
└── README.md
```

---

## 🛠️ Используемые технологии

- Go (Golang)
- PostgreSQL
- Docker, Docker Compose
- Gin
- Gorm
- JWT (SHA512)
- bcrypt
- Swagger UI

---

## 🌐 CORS

В проекте настроен CORS:

- Разрешены заголовки Authorization
- Swagger UI работает корректно

---

## 🙌 Авторы

- 👤 [Максим](https://github.com/himka0-0)

---

