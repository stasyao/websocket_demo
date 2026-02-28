"""
WebSocket с нуля — реализация по RFC 6455
Сервер и клиент в одном модуле, запуск через multiprocessing.
"""

import asyncio
import base64
import hashlib
from multiprocessing import Event, Process
from multiprocessing.synchronize import Event as MPEvent
import os
import secrets
import struct
import time

# ======================
# Константы
# ======================

HOST = "127.0.0.1"
PORT = 8765

# GUID захардкожен в RFC 6455, раздел 1.3 (Opening Handshake)
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Опкоды фреймов
OP_CONTINUATION = 0x0
OP_TEXT         = 0x1
OP_BINARY       = 0x2
OP_CLOSE        = 0x8
OP_PING         = 0x9
OP_PONG         = 0xA

CONTROL_OPCODES = (OP_CLOSE, OP_PING, OP_PONG)

# Коды закрытия
CLOSE_NORMAL       = 1000
CLOSE_PROTO_ERROR  = 1002
CLOSE_INVALID_UTF8 = 1007
CLOSE_TOO_BIG      = 1009

# Лимит на размер сообщения (защита от атак на память)
MAX_PAYLOAD = 1 * 1024 * 1024  # 1 МБ


# ======================
# Логирование
# ======================

def log(side: str, direction: str, level: str, msg: str):
    ts = time.strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}"
    print(f"[{ts}] {side:<6} {direction} [{level}] {msg}", flush=True)


# ========================
# Вспомогательные функции
# ========================

def apply_mask(data: bytes, mask: bytes) -> bytes:
    """Маскирование/демаскирование."""
    return bytes(b ^ mask[i % 4] for i, b in enumerate(data))


def compute_accept_key(key: str) -> str:
    """Вычисляет Sec-WebSocket-Accept из Sec-WebSocket-Key (RFC 6455, раздел 1.3)"""
    sha1 = hashlib.sha1((key + GUID).encode()).digest()
    return base64.b64encode(sha1).decode()


def generate_key() -> str:
    """Генерирует криптографически случайный Sec-WebSocket-Key."""
    return base64.b64encode(secrets.token_bytes(16)).decode()


# ===================================
# Чтение HTTP-заголовков рукопожатия
# ===================================
async def read_http_headers(reader: asyncio.StreamReader) -> str:
    """
    Читает HTTP-запрос/ответ до разделителя \\r\\n\\r\\n.
    Возвращает данные до разделителя; возможные последующие байты остаются
    во внутреннем буфере StreamReader для последующего чтения как WebSocket-фреймы.
    """
    data = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
    return data.decode("utf-8", errors="replace")


# ===================================
# Сериализатор фреймов
# ===================================

def build_frame(payload: bytes, opcode: int, mask: bool = False) -> bytes:
    """
    Собирает WebSocket-фрейм.
    mask=True для клиента (RFC 6455 в разд. 5.1 требует маскировать все фреймы клиента).
    Управляющие фреймы (CLOSE, PING, PONG): payload <= 125 байт, всегда FIN=1.
    """
    if opcode in CONTROL_OPCODES and len(payload) > 125:
        raise ValueError(f"Payload управляющего фрейма слишком велик: {len(payload)} байт (макс 125)")

    if len(payload) > MAX_PAYLOAD:
        raise ValueError(f"Payload слишком велик: {len(payload)} байт")

    fin_and_opcode = 0x80 | opcode  # FIN=1, RSV1-3=0
    length = len(payload)

    if length <= 125:
        len_byte = length
        ext_len = b""
    elif length <= 65535:
        len_byte = 126
        ext_len = struct.pack(">H", length)
    else:
        len_byte = 127
        ext_len = struct.pack(">Q", length)

    if mask:
        masking_key = os.urandom(4)
        masked_payload = apply_mask(payload, masking_key)
        return bytes([fin_and_opcode, 0x80 | len_byte]) + ext_len + masking_key + masked_payload
    else:
        return bytes([fin_and_opcode, len_byte]) + ext_len + payload


# =====================================
# Парсер фреймов (RFC 6455, раздел 5.2)
# =====================================

def _validate_rsv_bits(rsv: int) -> None:
    """Валидирует RSV-биты согласно RFC 6455, раздел 5.2 (Base Framing Protocol)."""
    if rsv != 0:
        raise ValueError(
            f"Ненулевые RSV-биты без согласованного расширения: 0x{rsv:02X} "
            f"(RFC 6455 §5.2)"
        )


async def _parse_frame_length(reader: asyncio.StreamReader, len_byte: int) -> int:
    """
    Парсит длину payload из фрейма.
    Читает расширенные поля длины при необходимости (2 или 8 байт).
    Валидирует минимальное кодирование (RFC 6455, раздел 5.2).
    """
    if len_byte == 126:
        length = struct.unpack(">H", await reader.readexactly(2))[0]
        if length <= 125:
            raise ValueError(
                f"Не минимальное кодирование длины: {length} закодировано "
                f"через 126 вместо одного байта (RFC 6455, 5.2)"
            )
    elif len_byte == 127:
        length = struct.unpack(">Q", await reader.readexactly(8))[0]
        if length >> 63:
            raise ValueError(
                f"Старший бит 64-битного поля длины не равен нулю: {length} "
                f"(RFC 6455 §5.2)"
            )
        if length <= 65535:
            raise ValueError(
                f"Не минимальное кодирование длины: {length} закодировано "
                f"через 127 вместо двух байт (RFC 6455, 5.2)"
            )
    else:
        length = len_byte
    return length


def _validate_control_frame_constraints(opcode: int, fin: bool, length: int) -> None:
    """
    Валидирует ограничения управляющих фреймов.
    Управляющие фреймы не могут быть фрагментированы и должны быть ≤ 125 байт.
    RFC 6455, раздел 5.5 (Control Frames).
    """
    if opcode in CONTROL_OPCODES:
        if not fin:
            raise ValueError("Управляющий фрейм не может быть фрагментирован (FIN=0)")
        if length > 125:
            raise ValueError(f"Payload управляющего фрейма слишком велик: {length} байт")


async def _read_and_unmask_payload(
    reader: asyncio.StreamReader,
    length: int,
    masked: bool
) -> bytes:
    """
    Читает payload из потока и демаскирует если необходимо.
    Маскирование согласно RFC 6455, раздел 5.3 (Client-to-Server Masking).
    """
    masking_key = await reader.readexactly(4) if masked else b""
    payload = await reader.readexactly(length)
    if masked:
        payload = apply_mask(payload, masking_key)
    return payload


async def parse_frame(reader: asyncio.StreamReader) -> tuple[int, bool, bool, bytes]:
    """
    Читает один WebSocket-фрейм из потока.
    Возвращает (opcode, fin, masked, payload).

    RFC 6455, раздел 5.2 (Base Framing Protocol).

    masked возвращается наружу для валидации на уровне выше:
    - клиентские фреймы обязаны быть замаскированы (MASK=1)
    - серверные фреймы никогда не маскируются (MASK=0)
    Нарушение -> закрытие с кодом 1002.
    """
    # Чтение и парсинг заголовка
    header = await reader.readexactly(2)
    fin = bool(header[0] & 0x80)
    rsv = header[0] & 0x70  # RSV1, RSV2, RSV3
    opcode = header[0] & 0x0F
    masked = bool(header[1] & 0x80)
    len_byte = header[1] & 0x7F

    # Валидация RSV-битов
    _validate_rsv_bits(rsv)

    # Парсинг длины с валидацией кодирования
    length = await _parse_frame_length(reader, len_byte)

    # Проверка максимального размера
    if length > MAX_PAYLOAD:
        raise ValueError(f"Фрейм слишком большой: {length} байт (макс {MAX_PAYLOAD})")

    # Валидация управляющих фреймов
    _validate_control_frame_constraints(opcode, fin, length)

    # Чтение и демаскирование payload
    payload = await _read_and_unmask_payload(reader, length, masked)

    return opcode, fin, masked, payload


# ===================================
# Управляющие фреймы
# ===================================

async def send_ping(writer: asyncio.StreamWriter, payload: bytes = b"", mask: bool = False):
    """Отправляет пинг-фрейм. RFC 6455, раздел 5.5.2."""
    writer.write(build_frame(payload, OP_PING, mask=mask))
    await writer.drain()


async def send_pong(writer: asyncio.StreamWriter, payload: bytes = b"", mask: bool = False):
    """Отправляет понг-фрейм. RFC 6455, раздел 5.5.3."""
    writer.write(build_frame(payload, OP_PONG, mask=mask))
    await writer.drain()


async def send_close(
    writer: asyncio.StreamWriter,
    code: int = CLOSE_NORMAL,
    reason: str = "",
    mask: bool = False,
) -> None:
    """
    Отправляет закрывающий фрейм. RFC 6455, раздел 5.5.1.

    Коды 1005, 1006, 1015 зарезервированы и не должны передаваться по сети.
    Полезная нагрузка длиной 1 байт означает ошибку протокола (должен быть либо пустым, либо >= 2 байт).
    """
    if code in (1005, 1006, 1015):
        raise ValueError(f"Код {code} зарезервирован и не должен отправляться в закрывающем фрейме")
    payload = struct.pack(">H", code) + reason.encode("utf-8")
    writer.write(build_frame(payload, OP_CLOSE, mask=mask))
    await writer.drain()


def validate_close_code(code: int) -> bool:
    """
    Проверяет, что код закрытия допустим для получения по сети.
    RFC 6455, раздел 7.1.5 (Status Codes).

    Коды 1005, 1006, 1015 зарезервированы и не должны передаваться по сети.
    """
    if code < 1000 or code > 4999:
        return False
    # Зарезервированные коды, которые не должны передаваться по сети
    if code in (1004, 1005, 1006, 1015):
        return False
    # Зарезервированные диапазоны
    if 1016 <= code <= 1999:
        return False
    if 2000 <= code <= 2999:
        return False
    return True


async def handle_close(
    writer: asyncio.StreamWriter,
    payload: bytes,
    mask: bool = False,
    side: str = "UNKNOWN",
):
    """
    Отвечает на входящий фрейм закрытия.
    RFC 6455, раздел 7.1.5 (Close Handshake).
    """
    if len(payload) == 0:
        # Пустой payload допустим, отвечаем тоже пустым закрывающим фреймом.
        # Локально код считается 1005, но 1005 не передаётся по сети.
        writer.write(build_frame(b"", OP_CLOSE, mask=mask))
        await writer.drain()
        return

    if len(payload) == 1:
        # Полезная нагрузка длиной 1 байт является нарушением протокола.
        await send_close(writer, CLOSE_PROTO_ERROR, mask=mask)
        return

    code = struct.unpack(">H", payload[:2])[0]
    reason_bytes = payload[2:]

    # Валидация кода закрытия по RFC 6455
    if not validate_close_code(code):
        log(side, "!", "PROTO", f"Недопустимый код закрытия: {code}")
        await send_close(writer, CLOSE_PROTO_ERROR, mask=mask)
        return

    # Если указана причина закрытия, она должна быть валидной UTF-8 строкой.
    if reason_bytes:
        try:
            reason_bytes.decode("utf-8")
        except UnicodeDecodeError:
            await send_close(writer, CLOSE_INVALID_UTF8, mask=mask)
            return

    await send_close(writer, code, mask=mask)


# ===================================
# Диспетчер входящих фреймов (RFC 6455, раздел 5)
# ===================================

async def _validate_masking(
    masked: bool,
    is_client: bool,
    writer: asyncio.StreamWriter,
    out_mask: bool,
    side: str
) -> bool:
    """
    Валидирует бит маскирования фрейма.
    RFC 6455, раздел 5.3 (Client-to-Server Masking).
    Возвращает True если нужно закрыть соединение, False иначе.
    """
    expected_masked = not is_client
    if masked != expected_masked:
        log(side, "!", "PROTO",
            f"Нарушение маскирования: masked={masked}, ожидалось {expected_masked}")
        await send_close(writer, CLOSE_PROTO_ERROR, mask=out_mask)
        return True
    return False


async def _handle_control_frame(
    opcode: int,
    payload: bytes,
    writer: asyncio.StreamWriter,
    side: str,
    out_mask: bool,
    close_sent: bool
) -> tuple[bool, str | bytes | None]:
    """
    Обрабатывает управляющие фреймы (ping, pong, close).
    RFC 6455, раздел 5.5 (Control Frames).
    Возвращает (should_close, message).
    """
    if opcode == OP_PING:
        log(side, "->", "FRAME", f"opcode=PONG len={len(payload)}")
        await send_pong(writer, payload, mask=out_mask)
        return False, None

    if opcode == OP_PONG:
        log(side, "·", "FRAME", "opcode=PONG получен")
        return False, None

    if opcode == OP_CLOSE:
        if close_sent:
            log(side, "·", "FRAME", "opcode=CLOSE после отправки нашего закрывающего фрейма (ответ не отправляем)")
        else:
            log(side, "->", "FRAME", "opcode=CLOSE (reply)")
            await handle_close(writer, payload, mask=out_mask, side=side)
        return True, None

    return False, None  # Не должен достигаться


def _manage_fragmentation(
    opcode: int,
    payload: bytes,
    fragments: list[bytes],
    fragment_opcode: list[int],
    side: str
) -> tuple[bool, str | bytes | None] | None:
    """
    Управляет фрагментацией сообщений.
    RFC 6455, раздел 5.4 (Fragmentation).
    Возвращает (should_close, message) при ошибке, None при продолжении.
    """
    if opcode in (OP_TEXT, OP_BINARY):
        if fragments:
            # Новый фрейм данных во время незавершённой фрагментации
            return True, None  # Сигнал для отправки close
        fragment_opcode.clear()
        fragment_opcode.append(opcode)
        fragments.append(payload)
    elif opcode == OP_CONTINUATION:
        if not fragments:
            # Continuation без начала фрагментации
            return True, None
        fragments.append(payload)
    else:
        log(side, "!", "PROTO", f"Неизвестный опкод 0x{opcode:X}, закрываем")
        return True, None

    return None


async def _assemble_and_decode_message(
    fragments: list[bytes],
    fragment_opcode: list[int],
    writer: asyncio.StreamWriter,
    side: str,
    out_mask: bool
) -> tuple[bool, str | bytes | None]:
    """
    Собирает фрагменты в полное сообщение и декодирует его.
    FC 6455, раздел 5.6 (Data Frames).
    Вызывается только когда fin=True.
    Возвращает (should_close, message).
    """
    full_payload = b"".join(fragments)
    if len(full_payload) > MAX_PAYLOAD:
        await send_close(writer, CLOSE_TOO_BIG, mask=out_mask)
        return True, None

    fragments.clear()
    orig_opcode = fragment_opcode[0] if fragment_opcode else OP_TEXT

    if orig_opcode == OP_TEXT:
        try:
            message = full_payload.decode("utf-8")
        except UnicodeDecodeError:
            log(side, "!", "PROTO", "Некорректный UTF-8 в текстовом фрейме, закрываем с кодом 1007")
            await send_close(writer, CLOSE_INVALID_UTF8, mask=out_mask)
            return True, None
        return False, message
    else:
        return False, full_payload


async def dispatch_frame(
    opcode: int,
    fin: bool,
    masked: bool,
    payload: bytes,
    writer: asyncio.StreamWriter,
    side: str,
    is_client: bool,
    close_sent: bool,
    fragments: list,
    fragment_opcode: list,
) -> tuple[bool, str | bytes | None]:
    """
    Обрабатывает входящий фрейм.
    Возвращает (should_close, message).
    """
    out_mask = is_client

    # Логирование
    opcode_names = {
        OP_CONTINUATION: "CONT",
        OP_TEXT:         "TEXT",
        OP_BINARY:       "BIN",
        OP_CLOSE:        "CLOSE",
        OP_PING:         "PING",
        OP_PONG:         "PONG",
    }
    opname = opcode_names.get(opcode, f"0x{opcode:X}")
    log(side, "<-", "FRAME",
        f"opcode={opname} fin={int(fin)} masked={int(masked)} len={len(payload)} "
        f"payload={payload[:20]!r}{'...' if len(payload) > 20 else ''}")

    # Валидация маскирования
    should_close = await _validate_masking(masked, is_client, writer, out_mask, side)
    if should_close:
        return True, None

    # Управляющие фреймы обрабатываем немедленно
    if opcode in CONTROL_OPCODES:
        return await _handle_control_frame(opcode, payload, writer, side, out_mask, close_sent)

    # Фреймы данных с поддержкой фрагментации
    result = _manage_fragmentation(opcode, payload, fragments, fragment_opcode, side)

    # Если _manage_fragmentation вернул не-None - это ошибка
    if result is not None:
        should_close, _ = result
        if should_close:
            await send_close(writer, CLOSE_PROTO_ERROR, mask=out_mask)
        return result

    # Если fin=True - собираем и декодируем сообщение
    if fin:
        return await _assemble_and_decode_message(fragments, fragment_opcode, writer, side, out_mask)

    return False, None


# ===================================
# СЕРВЕР (RFC 6455, раздел 4.2)
# ===================================
def validate_handshake(request_line: str, headers: dict) -> str | None:
    """
    Валидирует HTTP handshake запрос от клиента.
    RFC 6455, раздел 4.2.1 (Reading the Client's Opening Handshake).
    Возвращает причину ошибки или None если запрос валиден.
    """
    parts = request_line.split()
    if len(parts) < 3:
        return "некорректная строка запроса"
    if parts[0] != "GET":
        return "метод запроса должен быть GET (RFC 6455, раздел 4.2.1)"
    if parts[2] != "HTTP/1.1":
        return f"требуется HTTP/1.1 (RFC 6455, раздел 4.2.1), получено: {parts[2]}"
    if headers.get("upgrade", "").lower() != "websocket":
        return "отсутствует заголовок Upgrade: websocket"
    if "upgrade" not in headers.get("connection", "").lower():
        return "отсутствует заголовок Connection: Upgrade"
    if headers.get("sec-websocket-version") != "13":
        return "неверное значение в Sec-WebSocket-Version"
    if not headers.get("sec-websocket-key"):
        return "отсутствует заголовок Sec-WebSocket-Key"
    return None


async def _perform_server_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    side: str
) -> bool:
    """
    Выполняет серверную часть WebSocket handshake.
    Согласно RFC 6455, раздел 4.2 (Server-Side Requirements).
    Возвращает True если handshake успешен, False иначе.
    """
    try:
        request = await read_http_headers(reader)
    except Exception as e:
        log(side, "!", "ERROR", str(e))
        return False

    log(side, "<-", "HTTP", f"Получен запрос ({len(request)} байт)")

    headers = {}
    lines = request.split("\r\n")
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    async def bad_request(reason: str):
        log(side, "->", "HTTP", f"400 Bad Request: {reason}")
        writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        await writer.drain()
        writer.close()

    if error := validate_handshake(lines[0], headers):
        await bad_request(error)
        return False

    ws_key = headers["sec-websocket-key"]
    accept_key = compute_accept_key(ws_key)
    log(side, "·", "HAND", f"Sec-WebSocket-Key={ws_key}")
    log(side, "·", "HAND", f"Sec-WebSocket-Accept={accept_key}")

    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept_key}\r\n"
        "\r\n"
    )
    writer.write(response.encode())
    await writer.drain()
    log(side, "->", "HTTP", "101 Switching Protocols рукопожатие завершено")
    log(side, "·", "STATE", "OPEN")
    return True


async def _server_ticker(writer: asyncio.StreamWriter, side: str):
    """Отправляет периодические сообщения от сервера."""
    n = 0
    try:
        while True:
            await asyncio.sleep(1.5)
            n += 1
            msg = f"message from SERVER #{n}"
            log(side, "->", "APP", msg)
            log(side, "->", "FRAME", f"opcode=TEXT len={len(msg)}")
            writer.write(build_frame(msg.encode(), OP_TEXT, mask=False))
            await writer.drain()
    except Exception:
        pass


async def _run_server_message_loop(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    side: str,
    fragments: list[bytes],
    fragment_opcode: list[int]
):
    """
    Основной цикл обработки сообщений сервера.
    """
    try:
        while True:
            opcode, fin, masked, payload = await parse_frame(reader)

            should_close, message = await dispatch_frame(
                opcode, fin, masked, payload, writer,
                side=side, is_client=False,
                close_sent=False,  # сервер не инициирует закрытие в этом демо
                fragments=fragments, fragment_opcode=fragment_opcode,
            )

            if message is not None:
                log(side, "<-", "APP", repr(message))

            if should_close:
                log(side, "·", "STATE", "CLOSING -> CLOSED")
                break

    except asyncio.IncompleteReadError:
        log(side, "!", "TCP", "Соединение оборвалось (код 1006)")
    except ValueError as e:
        log(side, "!", "PROTO", str(e))
        try:
            code = CLOSE_TOO_BIG if "too large" in str(e) else CLOSE_PROTO_ERROR
            await send_close(writer, code, mask=False)
        except Exception:
            pass
    except Exception as e:
        log(side, "!", "ERROR", str(e))


async def _cleanup_server_connection(
    writer: asyncio.StreamWriter,
    ticker_task: asyncio.Task,
    side: str
):
    """Очищает ресурсы серверного подключения."""
    ticker_task.cancel()
    try:
        await ticker_task
    except asyncio.CancelledError:
        pass
    writer.close()
    await writer.wait_closed()
    log(side, "·", "STATE", "CLOSED")
    log(side, "·", "TCP", "TCP-соединение закрыто")


async def server_handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Обрабатывает одно серверное WebSocket-подключение."""
    side = "SERVER"
    addr = writer.get_extra_info("peername")
    log(side, "·", "TCP", f"Новое подключение от {addr}")

    # Рукопожатие
    if not await _perform_server_handshake(reader, writer, side):
        return

    # Инициализация состояния
    fragments: list[bytes] = []
    fragment_opcode: list[int] = []

    # Запуск ticker'а
    ticker_task = asyncio.create_task(_server_ticker(writer, side))

    # Основной цикл
    await _run_server_message_loop(reader, writer, side, fragments, fragment_opcode)

    # Очистка ресурсов
    await _cleanup_server_connection(writer, ticker_task, side)


async def run_server(ready_event: MPEvent):
    server = await asyncio.start_server(server_handle, HOST, PORT)
    ready_event.set()
    log("SERVER", "·", "TCP", f"Слушаем {HOST}:{PORT}")
    async with server:
        await server.serve_forever()


def server_process(ready_event: MPEvent):
    asyncio.run(run_server(ready_event))


# ===================================
# КЛИЕНТ
# ===================================
def validate_server_response(status_line: str, headers: dict, key: str) -> str | None:
    """
    Валидирует ответ сервера на запрос рукопожатия.
    RFC 6455, раздел 4.1 (Client Requirements).
    Возвращает причину ошибки или None если ответ валиден.
    """
    if "101 Switching Protocols" not in status_line:
        return f"ожидался статус 101 Switching Protocols, получено: {status_line}"
    if headers.get("upgrade", "").lower() != "websocket":
        return "неверный заголовок Upgrade в ответе сервера"
    if "upgrade" not in headers.get("connection", "").lower():
        return "неверный заголовок Connection в ответе сервера"
    expected_accept = compute_accept_key(key)
    actual_accept = headers.get("sec-websocket-accept", "")
    if actual_accept != expected_accept:
        return f"неверный Sec-WebSocket-Accept: {actual_accept} != {expected_accept}"
    return None


async def _perform_client_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    side: str
) -> bool:
    """
    Выполняет клиентскую часть WebSocket handshake.
    RFC 6455, раздел 4.1 (Client Requirements).
    Возвращает True если handshake успешен, False иначе.
    """
    key = generate_key()
    log(side, "·", "HAND", f"Sec-WebSocket-Key={key}")

    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    )
    writer.write(request.encode())
    await writer.drain()
    log(side, "->", "HTTP", "GET / HTTP/1.1 (запрос на рукопожатие)")

    response = await read_http_headers(reader)
    log(side, "<-", "HTTP", f"Получен ответ ({len(response)} байт)")

    lines = response.split("\r\n")
    status_line = lines[0]

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    if error := validate_server_response(status_line, headers, key):
        log(side, "!", "ERROR", error)
        return False

    log(side, "·", "HAND", f"Sec-WebSocket-Accept проверен: {compute_accept_key(key)}")
    log(side, "·", "STATE", "OPEN")
    return True


async def _client_sender(
    writer: asyncio.StreamWriter,
    side: str,
    close_sent_event: asyncio.Event
):
    """
    Отправляет периодические сообщения от клиента и инициирует закрытие.
    """
    n = 0
    try:
        while True:
            await asyncio.sleep(1.0)
            n += 1
            msg = f"message from CLIENT #{n}"
            log(side, "->", "APP", msg)
            log(side, "->", "FRAME", f"opcode=TEXT len={len(msg)} MASKED=1")
            writer.write(build_frame(msg.encode(), OP_TEXT, mask=True))
            await writer.drain()

            if n >= 5:
                await asyncio.sleep(0.5)
                log(side, "->", "APP", "Инициируем закрытие соединения")
                writer.write(build_frame(
                    struct.pack(">H", CLOSE_NORMAL) + "done".encode("utf-8"),
                    OP_CLOSE,
                    mask=True,
                ))
                close_sent_event.set()
                await writer.drain()
                break
    except Exception:
        pass


async def _run_client_message_loop(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    side: str,
    close_sent: asyncio.Event,
    fragments: list[bytes],
    fragment_opcode: list[int]
):
    """
    Основной цикл обработки сообщений клиента.
    """
    try:
        while True:
            opcode, fin, masked, payload = await parse_frame(reader)

            should_close, message = await dispatch_frame(
                opcode, fin, masked, payload, writer,
                side=side, is_client=True,
                close_sent=close_sent.is_set(),
                fragments=fragments, fragment_opcode=fragment_opcode,
            )

            if message is not None:
                log(side, "<-", "APP", repr(message))

            if should_close:
                log(side, "·", "STATE", "CLOSING")
                break

    except asyncio.IncompleteReadError:
        log(side, "!", "TCP", "Соединение оборвалось (код 1006)")
    except ValueError as e:
        log(side, "!", "PROTO", str(e))
        try:
            code = CLOSE_TOO_BIG if "too large" in str(e) else CLOSE_PROTO_ERROR
            await send_close(writer, code, mask=True)
        except Exception:
            pass
    except Exception as e:
        log(side, "!", "ERROR", str(e))


async def _cleanup_client_connection(
    writer: asyncio.StreamWriter,
    sender_task: asyncio.Task,
    reader: asyncio.StreamReader,
    side: str
):
    """Очищает ресурсы клиентского подключения."""
    sender_task.cancel()
    try:
        await sender_task
    except asyncio.CancelledError:
        pass
    try:
        await reader.read(1)
    except Exception:
        pass
    writer.close()
    await writer.wait_closed()
    log(side, "·", "STATE", "CLOSED")
    log(side, "·", "TCP", "TCP-соединение закрыто")


async def run_client():
    """Клиент WebSocket-соединения."""
    side = "CLIENT"

    reader, writer = await asyncio.open_connection(HOST, PORT)
    log(side, "·", "TCP", f"Подключились к {HOST}:{PORT}")

    # Рукопожатие
    if not await _perform_client_handshake(reader, writer, side):
        writer.close()
        return

    # Инициализация состояния
    close_sent = asyncio.Event()
    fragments: list[bytes] = []
    fragment_opcode: list[int] = []

    # Запуск sender'а
    sender_task = asyncio.create_task(_client_sender(writer, side, close_sent))

    # Основной цикл
    await _run_client_message_loop(reader, writer, side, close_sent, fragments, fragment_opcode)

    # Очистка ресурсов
    await _cleanup_client_connection(writer, sender_task, reader, side)


def client_process(ready_event: MPEvent):
    ready_event.wait()
    asyncio.run(run_client())


# ===================================
# Точка входа
# ===================================

if __name__ == "__main__":
    ready = Event()

    srv = Process(target=server_process, args=(ready,), name="ws-server")
    cli = Process(target=client_process, args=(ready,), name="ws-client")

    srv.start()
    cli.start()

    cli.join()
    srv.terminate()
    srv.join()
