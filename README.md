# Постигаем протокол веб-сокетов

Реализация протокола WebSocket ([RFC 6455](https://www.rfc-editor.org/rfc/rfc6455)) на чистом Python без сторонних зависимостей. Только стандартная библиотека: `asyncio`, `hashlib`, `struct`, `secrets`.

Код написан как учебный материал к статье ["Анатомия WebSocket: человечный разбор RFC 6455"](https://habr.com/ru/articles/1004772/). Каждый шаг жизненного цикла соединения отражен в отдельной функции.

## Запуск

```bash
python websocket_demo.py
```

## Общая логика работы

Сервер и клиент запускаются в отдельных процессах через `multiprocessing`, каждый со своим событийным циклом, все как в реальности. Просто в данном случае код и клиента, и сервера сведены в один модуль для удобства (можно сразу запустить и увидеть обмен, а не открывать 2 отдельных терминала, в которых запускать 2 отдельных модуля).

После рукопожатия обе стороны переходят в режим полноценного двустороннего обмена:

- клиент отправляет текстовый фрейм каждую секунду
- сервер независимо от клиента каждые 1.5 секунды.

Оба потока сообщений идут одновременно по одному TCP-соединению, не блокируя друг друга: именно это и отличает веб-сокеты от классического цикла "запрос-ответ" в HTTP.

Параллельно сервер периодически отправляет ping-фреймы. Клиент отвечает pong-фреймами, не прерывая основной поток сообщений.

После отправки 5 сообщений клиент инициирует корректное закрытие:

- отправляет закрывающий фрейм с кодом 1000
- ждет ответного закрывающего фрейма от сервера
- затем ждет TCP FIN-сегмента и только после этого закрывает соединение.

Сервер останавливается автоматически после завершения клиентского процесса.

Таким образом в рамках одного запуска демонстрируются все 3 фазы протокола:

- открытие соединения
- двусторонняя передача данных с управляющими фреймами
- корректное закрытие соединения

Весь жизненный цикл подробно логируется в консоль, что тоже служит хорошим источником для понимания логики работы веб-сокетов.

## Пример вывода в консоль

Пример вывода:

```
[11:41:35.963] SERVER · [TCP] Слушаем 127.0.0.1:8765
[11:41:35.965] CLIENT · [TCP] Подключились к 127.0.0.1:8765
[11:41:35.965] SERVER · [TCP] Новое подключение от ('127.0.0.1', 39826)
[11:41:35.965] CLIENT · [HAND] Sec-WebSocket-Key=ptmPzmtykTeT+Mbrpsb8vQ==
[11:41:35.966] CLIENT -> [HTTP] GET / HTTP/1.1 (запрос на рукопожатие)
[11:41:35.966] SERVER <- [HTTP] Получен запрос (153 байт)
[11:41:35.966] SERVER · [HAND] Sec-WebSocket-Key=ptmPzmtykTeT+Mbrpsb8vQ==
[11:41:35.966] SERVER · [HAND] Sec-WebSocket-Accept=zmfstbuT8b+4rBD33rzKcupxDzk=
[11:41:35.966] SERVER -> [HTTP] 101 Switching Protocols рукопожатие завершено
[11:41:35.966] SERVER · [STATE] OPEN
[11:41:35.966] CLIENT <- [HTTP] Получен ответ (129 байт)
[11:41:35.966] CLIENT · [HAND] Sec-WebSocket-Accept проверен: zmfstbuT8b+4rBD33rzKcupxDzk=
[11:41:35.966] CLIENT · [STATE] OPEN
[11:41:36.967] CLIENT -> [APP] message from CLIENT #1
[11:41:36.967] CLIENT -> [FRAME] opcode=TEXT len=22 MASKED=1
[11:41:36.968] SERVER <- [FRAME] opcode=TEXT fin=1 masked=1 len=22 payload=b'message from CLIENT '...
[11:41:36.968] SERVER <- [APP] 'message from CLIENT #1'
[11:41:37.467] SERVER -> [APP] message from SERVER #1
[11:41:37.467] SERVER -> [FRAME] opcode=TEXT len=22
[11:41:37.467] CLIENT <- [FRAME] opcode=TEXT fin=1 masked=0 len=22 payload=b'message from SERVER '...
[11:41:37.467] CLIENT <- [APP] 'message from SERVER #1'
[11:41:37.969] CLIENT -> [APP] message from CLIENT #2
[11:41:37.969] CLIENT -> [FRAME] opcode=TEXT len=22 MASKED=1
[11:41:37.970] SERVER <- [FRAME] opcode=TEXT fin=1 masked=1 len=22 payload=b'message from CLIENT '...
[11:41:37.970] SERVER <- [APP] 'message from CLIENT #2'
[11:41:38.969] SERVER -> [APP] message from SERVER #2
[11:41:38.969] SERVER -> [FRAME] opcode=TEXT len=22
[11:41:38.969] CLIENT <- [FRAME] opcode=TEXT fin=1 masked=0 len=22 payload=b'message from SERVER '...
[11:41:38.969] CLIENT <- [APP] 'message from SERVER #2'
[11:41:38.969] CLIENT -> [APP] message from CLIENT #3
[11:41:38.969] CLIENT -> [FRAME] opcode=TEXT len=22 MASKED=1
[11:41:38.970] SERVER <- [FRAME] opcode=TEXT fin=1 masked=1 len=22 payload=b'message from CLIENT '...
[11:41:38.970] SERVER <- [APP] 'message from CLIENT #3'
[11:41:39.971] CLIENT -> [APP] message from CLIENT #4
[11:41:39.971] CLIENT -> [FRAME] opcode=TEXT len=22 MASKED=1
[11:41:39.972] SERVER <- [FRAME] opcode=TEXT fin=1 masked=1 len=22 payload=b'message from CLIENT '...
[11:41:39.972] SERVER <- [APP] 'message from CLIENT #4'
[11:41:40.470] SERVER -> [APP] message from SERVER #3
[11:41:40.471] SERVER -> [FRAME] opcode=TEXT len=22
[11:41:40.471] CLIENT <- [FRAME] opcode=TEXT fin=1 masked=0 len=22 payload=b'message from SERVER '...
[11:41:40.471] CLIENT <- [APP] 'message from SERVER #3'
[11:41:41.768] CLIENT -> [APP] message from CLIENT #5
[11:41:41.768] CLIENT -> [FRAME] opcode=TEXT len=22 MASKED=1
[11:41:41.769] SERVER <- [FRAME] opcode=TEXT fin=1 masked=1 len=22 payload=b'message from CLIENT '...
[11:41:41.769] SERVER <- [APP] 'message from CLIENT #5'
[11:41:42.269] CLIENT -> [APP] Инициируем закрытие соединения
[11:41:42.270] SERVER <- [FRAME] opcode=CLOSE fin=1 masked=1 len=6 payload=b'\x03\xe8done'
[11:41:42.270] SERVER -> [FRAME] opcode=CLOSE (reply)
[11:41:42.270] SERVER · [STATE] CLOSING -> CLOSED
[11:41:42.270] CLIENT <- [FRAME] opcode=CLOSE fin=1 masked=0 len=2 payload=b'\x03\xe8'
[11:41:42.270] CLIENT · [FRAME] opcode=CLOSE после отправки нашего закрывающего фрейма (ответ не отправляем)
[11:41:42.270] CLIENT · [STATE] CLOSING
[11:41:42.270] SERVER · [STATE] CLOSED
[11:41:42.270] SERVER · [TCP] TCP-соединение закрыто
[11:41:42.271] CLIENT · [STATE] CLOSED
[11:41:42.271] CLIENT · [TCP] TCP-соединение закрыто
```

## Структура модуля

- **Константы и опкоды** — `OP_TEXT`, `OP_BINARY`, `OP_PING`, `OP_PONG`, `OP_CLOSE`, `CLOSE_NORMAL` и др.

- **Вспомогательные функции**
  - `apply_mask()` — маскирование/демаскирование payload
  - `compute_accept_key()` — SHA-1 + base64 для Sec-WebSocket-Accept
  - `generate_key()` — криптографически случайный Sec-WebSocket-Key

- **Рукопожатие**
  - `read_http_headers()` — чтение HTTP-запроса/ответа до \r\n\r\n
  - `validate_handshake()` — валидация входящего запроса на стороне сервера
  - `validate_server_response()` — валидация ответа 101 на стороне клиента

- **Фрейминг**
  - `build_frame()` — сборка фрейма: FIN + RSV + opcode + length + [mask] + payload
  - `parse_frame()` — разбор входящего фрейма
    - `_validate_rsv_bits()` — валидация RSV-битов
    - `_parse_frame_length()` — парсинг длины с валидацией минимального кодирования
    - `_validate_control_frame_constraints()` — проверка ограничений управляющих фреймов
    - `_read_and_unmask_payload()` — чтение и демаскирование payload

- **Управляющие фреймы**
  - `send_ping()` / `send_pong()` — пинг-понг для проверки жизнеспособности соединения
  - `send_close()` — отправка закрывающего фрейма
  - `handle_close()` — ответ на входящий закрывающий фрейм
  - `validate_close_code()` — проверка допустимости кода закрытия

- **Диспетчер**
  - `dispatch_frame()` — маршрутизация фреймов по опкодам
    - `_validate_masking()` — валидация MASK-бита (клиент MASK=1, сервер MASK=0)
    - `_handle_control_frame()` — обработка PING/PONG/CLOSE
    - `_manage_fragmentation()` — управление сборкой фрагментированных сообщений
    - `_assemble_and_decode_message()` — сборка фрагментов и декодирование UTF-8

- **Сервер**
  - `server_handle()` — обработчик одного соединения
    - `_perform_server_handshake()` — выполнение WebSocket-рукопожатия
    - `_server_ticker()` — отправка периодических сообщений
    - `_run_server_message_loop()` — основной цикл обработки входящих фреймов
    - `_cleanup_server_connection()` — очистка ресурсов и закрытие TCP
  - `run_server()` — запуск asyncio-сервера

- **Клиент**
  - `run_client()` — полный цикл соединения
    - `_perform_client_handshake()` — выполнение WebSocket-рукопожатия
    - `_client_sender()` — отправка сообщений и инициация закрытия
    - `_run_client_message_loop()` — основной цикл обработки входящих фреймов
    - `_cleanup_client_connection()` — ожидание TCP FIN, очистка ресурсов

## Жизненный цикл соединения

### Открытие соединения

**Шаг 1. Клиент генерирует ключ**

```python
# generate_key()
base64.b64encode(secrets.token_bytes(16)).decode()
```

RFC 6455 требует криптографически случайное 16-байтовое значение, закодированное в base64. `secrets.token_bytes` гарантирует криптографическую случайность в отличие от `random`.

**Шаг 2. Клиент открывает TCP и отправляет GET-запрос по HTTP/1.1**

```python
# run_client()
reader, writer = await asyncio.open_connection(HOST, PORT)
writer.write(request.encode())
await writer.drain()
```

Запрос содержит 5 обязательных заголовков:

- `Host`
- `Upgrade: websocket`
- `Connection: Upgrade`
- `Sec-WebSocket-Key`
- `Sec-WebSocket-Version: 13`

**Шаг 3. Сервер принимает запрос и валидирует заголовки**

```python
# read_http_headers() — читает до \r\n\r\n, лимит MAX_HANDSHAKE_SIZE
# validate_handshake() — проверяет метод, версию HTTP, все обязательные заголовки
if error := validate_handshake(lines[0], headers):
    await bad_request(error)
    return
```

`validate_handshake` проверяет: метод `GET`, версию `HTTP/1.1` (RFC 6455, разд. 4.2.1), наличие заголовков `Upgrade`, `Connection`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`.

**Шаг 4. Сервер вычисляет `Sec-WebSocket-Accept`**

```python
# compute_accept_key()
sha1 = hashlib.sha1((key + GUID).encode()).digest()
return base64.b64encode(sha1).decode()
```

`GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"` захардкожен в RFC 6455. Это не случайное значение, оно одинаково во всех реализациях протокола в мире.

**Шаг 5. Сервер отвечает `101 Switching Protocols`**

```python
# server_handle()
response = (
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Accept: {accept_key}\r\n"
    "\r\n"
)
```

**Шаг 6. Клиент валидирует ответ, обе стороны переходят в `OPEN`**

```python
# validate_server_response()
# проверяет статус 101, заголовки Upgrade/Connection,
# и что Sec-WebSocket-Accept совпадает с ожидаемым значением
if error := validate_server_response(status_line, headers, key):
    log(side, "!", "ERROR", error)
    writer.close()
    return
```

После этой точки HTTP-соединение становится WebSocket-соединением.

### Передача данных

**Шаг 7. Клиент формирует фрейм**

```python
# build_frame(payload, opcode, mask=True)
fin_and_opcode = 0x80 | opcode # FIN=1, RSV1-3=0
```

RFC 6455: все фреймы от клиента к серверу **обязаны** быть замаскированы (`mask=True`). `build_frame` генерирует случайный 4-байтовый маскирующий ключ через `os.urandom(4)`.

Кодирование длины:

- `0–125` байт -> 1 байт
- `126–65535` байт -> байт `126` + 2 байта длины
- `> 65535` байт -> байт `127` + 8 байт длины

**Шаг 8. Сервер принимает фрейм и демаскирует**

```python
# parse_frame()
# проверяет RSV-биты, минимальное кодирование длины, MSB у 64-битной длины
# apply_mask(payload, masking_key) — XOR каждого байта с mask[i % 4]
```

`parse_frame` реализует три проверки из RFC 6455:

- поле RSV1-3 должно быть 0 при отсутствии согласованных расширений
- длина должна кодироваться минимальным числом байт
- старший бит 64-битного поля длины должен быть 0

**Шаги 9 и 10. Диспетчеризация по опкоду**

```python
# dispatch_frame()
# маршрутизирует входящий фрейм по опкоду:
# TEXT(0x1), BINARY(0x2) -> сборка фрагментов -> decode UTF-8 или bytes
# CONTINUATION(0x0)      -> накопление фрагментов
# PING(0x9)              -> немедленный PONG с тем же пэйлоадом
# PONG(0xA)              -> логирование, игнорирование
# CLOSE(0x8)             -> handle_close() или завершение
# неизвестный опкод      -> закрытие с кодом 1002
```

Валидация MASK-бита выполняется здесь же: сервер ожидает `MASK=1`, клиент ожидает `MASK=0`. Нарушение → закрытие с кодом 1002.

**Шаг 11. Пинг-понг**

```python
# send_ping() / send_pong()
# сервер отправляет пинг каждые N секунд через ticker()
# dispatch_frame при получении PING немедленно вызывает send_pong()
```

В демо пинг инициирует сервер. Клиент отвечает понгом автоматически внутри `dispatch_frame`.

### Закрытие соединения

**Шаг 12. Инициатор отправляет закрывающий фрейм**

```python
# send_close()
payload = struct.pack(">H", code) + reason.encode("utf-8")
# код 1000 = нормальное закрытие
# коды 1005, 1006, 1015 зарезервированы и не отправляются по сети
```

В демо закрытие инициирует клиент после отправки 5 сообщений. Запись фрейма в буфер и установка флага `close_sent` происходят **до** `await writer.drain()` — это исключает гонку между `sender()` и основным циклом чтения.

**Шаг 13. Получатель отвечает закрывающим фреймом**

```python
# handle_close()
# проверяет payload: пустой (код 1000), 1 байт (ошибка протокола),
# >= 2 байт: валидирует код через validate_close_code()
# затем отправляет ответный закрывающий фрейм с тем же кодом
```

**Шаг 14. TCP закрывается асимметрично**

```python
# server_handle():
writer.close()
# сервер закрывает немедленно
await writer.wait_closed()

# run_client():
# клиент ждёт TCP FIN от сервера
await reader.read(1)
writer.close()
await writer.wait_closed()
```

Асимметрия намеренна (RFC 6455, параграф 7.1.1): сервер должен закрывать TCP первым, чтобы именно он удерживал состояние `TIME_WAIT`, а не клиент. Для клиента `TIME_WAIT` означает, что он не может переоткрыть то же соединение в течение 2MSL (двух максимальных времен жизни TCP-сегмента). Для сервера удержание `TIME_WAIT` не создает аналогичных проблем, потому что новое входящее `SYN` с большим порядковым номером немедленно открывает новое соединение.

**Шаги 15. Обе стороны переходят в `CLOSED`**

```python
log(side, "·", "STATE", "CLOSED")
log(side, "·", "TCP", "TCP-соединение закрыто")
```

### Аномальное закрытие

**Шаг 16. Если соединение оборвалось без закрывающего фрейма, то возвращается код 1006**

```python
except asyncio.IncompleteReadError:
    log(side, "!", "TCP", "Соединение оборвалось (код 1006)")
```

`IncompleteReadError` означает, что TCP-соединение закрылось в середине чтения фрейма. Код 1006 зарезервирован именно для этого случая и никогда не передается по сети, только фиксируется локально.

**Шаг 17. Переподключение с экспоненциальной задержкой**

В демо переподключение не реализовано, это учебный пример одного соединения. Логика переподключения описана в статье и выглядит так:

```python
async def reconnect_with_backoff():
    delay = random.uniform(0, 5) # случайная начальная задержка (RFC 6455, параграф 7.2.3)
    max_delay = 60

    while True:
        await asyncio.sleep(delay)
        try:
            await connect()
            break
        except Exception:
            delay = min(delay * 2, max_delay)   # экспоненциальный откат
```

Случайная начальная задержка размазывает волну одновременных переподключений во времени. Тысячи клиентов, потерявших соединение в один момент, не ломятся на сервер одновременно.

## Что намеренно не реализовано

Это учебный модуль. В нем нет вещей, которые усложнили бы код без пользы для понимания протокола:

- TLS / `wss://` требует обёртки TCP-соединения в `ssl.SSLContext`, не меняет протокол WebSocket
- Расширения (`permessage-deflate` и др.) — согласовываются при рукопожатии через `Sec-WebSocket-Extensions`
- Субпротоколы согласовываются через `Sec-WebSocket-Protocol`
- Переподключение — логика описана в статье, в демо одно соединение
- Несколько клиентов — сервер поддерживает несколько подключений через `asyncio`, но демо запускает одного клиента

## Соответствие RFC 6455

| Требование                                     | Раздел RFC | Реализовано                         |
| ---------------------------------------------- | ---------- | ----------------------------------- |
| Метод GET, версия HTTP/1.1                     | 4.1        | `validate_handshake`                |
| Криптографически случайный 16-байтовый ключ    | 4.1        | `generate_key`                      |
| Обязательные заголовки запроса клиента         | 4.1        | `run_client`                        |
| Валидация входящего запроса на сервере         | 4.2.1      | `validate_handshake`                |
| Вычисление `Sec-WebSocket-Accept`              | 4.2.2      | `compute_accept_key`                |
| Валидация ответа сервера клиентом              | 4.1        | `validate_server_response`          |
| Маскирование фреймов клиента                   | 5.3        | `build_frame(mask=True)`            |
| Валидация MASK-бита                            | 5.1        | `dispatch_frame`                    |
| RSV-биты должны быть 0                         | 5.2        | `parse_frame`                       |
| Минимальное кодирование длины                  | 5.2        | `parse_frame`                       |
| MSB у 64-битной длины равен 0                  | 5.2        | `parse_frame`                       |
| Управляющие фреймы <= 125 байт                 | 5.5        | `build_frame`, `parse_frame`        |
| Управляющие фреймы не фрагментируются          | 5.5        | `parse_frame`                       |
| Сборка фрагментированных сообщений             | 5.4        | `dispatch_frame`                    |
| Неизвестный опкод -> закрытие с кодом 1002     | 5.2        | `dispatch_frame`                    |
| Пинг -> немедленный понг с идентичным payload  | 5.5.2      | `dispatch_frame`, `send_pong`       |
| Зарезервированные коды не отправляются по сети | 7.4        | `send_close`, `validate_close_code` |
| Невалидный UTF-8 -> код 1007                   | 8.1        | `dispatch_frame`, `handle_close`    |
| TCP-асимметрия при закрытии                    | 7.1.1      | `run_client`                        |
| Аномальное закрытие -> код 1006                | 7.1.5      | `server_handle`, `run_client`       |
