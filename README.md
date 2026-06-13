# Validation Service

Веб апликација за валидација на дигитални потписи и сертификати, изградена со Spring Boot. Сервисот поддржува верификација на потписи во PDF документи, Office документи, самостојни сертификати и `.p7s` потписи, со поддршка за македонски trusted root CA сертификати (KIBS и Telekom).

---

## Технологии

- **Java 17**
- **Spring Boot 3.5** (Web, JPA, Thymeleaf, SSL)
- **PostgreSQL** — за чување историја на валидации
- **Apache PDFBox 3.0.2** — парсирање на PDF потписи
- **Bouncy Castle 1.78** — криптографска верификација (CMS/PKCS#7)

---

## Поддржани формати

| Формат | Опис |
|--------|------|
| `.pdf` | PDF со вграден дигитален потпис |
| `.cer` / `.crt` / `.der` | Самостоен X.509 сертификат |
| `.p7s` | CAdES / PKCS#7 detached потпис |
| `.docx` / `.pptx` / `.xlsx` | Microsoft Office документи со XAdES потпис |

---

## Поставување

### Барања

- Java 17+
- PostgreSQL (порт `5433`)
- SSL keystore (`.p12`)

### База на податоци

Креирај база:

```sql
CREATE DATABASE validation_db;
```

### Конфигурација

Во `src/main/resources/application.properties` пополни:

```properties
spring.datasource.username=<корисник>
spring.datasource.password=<лозинка>
server.ssl.key-store-password=<keystore лозинка>
```

### Стартување

```bash
./mvnw spring-boot:run
```

Апликацијата се стартува на `https://localhost:8443`.

---

## Функционалност

### Валидација на PDF
Ги верификува сите вградени CMS/PKCS#7 потписи. Го идентификува потписникот преку CN од сертификатот, проверува временска важност и го верифицира синџирот на доверба.

### Самостоен сертификат (`.cer` / `.crt` / `.der`)
Парсира X.509 сертификат, проверува дали е истечен и го верифицира синџирот кон trusted root.

### P7S потпис
Верификува CAdES/PKCS#7 detached потпис, ги идентификува потписникот и издавачот.

### Office документи
Ги извлекува X.509 сертификатите од OOXML ZIP структурата и верифицира XAdES потпис.

---

## Trusted Root CA

Сервисот ги вклучува следните македонски root CA сертификати:

- **KIBS Root CA**
- **KIBS Issuing G2 CA**
- **Telekom Root CA**

Сместени во: `src/main/resources/trusted-roots/`

---

## База на податоци

Историјата на валидации се чува во табелата `validation_logs`:

| Колона | Тип | Опис |
|--------|-----|------|
| `id` | BIGINT | Примарен клуч |
| `file_name` | VARCHAR | Име на документот |
| `signer_name` | VARCHAR | Потписник и статус |
| `is_valid` | BOOLEAN | Резултат од валидацијата |
| `validation_time` | TIMESTAMP | Време на валидација |

---

## Безбедност

- Апликацијата комуницира исклучиво преку **HTTPS** (порт 8443)
