#!/usr/bin/env python3
"""Build a portable, ZIP-free context package for offline firmware analysis."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "llm-handoff"
RAW = OUT / "raw"
EV = OUT / "evidence"
PATCHES = OUT / "patches"
TOOLS = OUT / "tools"
IMAGES = OUT / "images"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def printable_strings(data: bytes, minimum: int = 4) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    start = None
    buf = bytearray()
    for i, b in enumerate(data + b"\x00"):
        if 0x20 <= b <= 0x7E:
            if start is None:
                start = i
            buf.append(b)
        else:
            if start is not None and len(buf) >= minimum:
                result.append((start, buf.decode("ascii")))
            start = None
            buf.clear()
    return result


def hex_dump(data: bytes, base: int = 0, width: int = 16) -> str:
    lines = []
    for pos in range(0, len(data), width):
        chunk = data[pos:pos + width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
        lines.append(f"{base + pos:08x}  {hx:<47}  |{asc}|")
    return "\n".join(lines)


def parse_attack_catalog(report: str) -> list[dict]:
    rows = []
    for line in report.splitlines():
        if not line.startswith("| M"):
            continue
        cols = [x.strip() for x in line.strip().strip("|").split("|")]
        if len(cols) != 6:
            continue
        method_id, method, kind, complexity, status, proof = cols
        rows.append({
            "id": method_id,
            "method": method.replace("`", ""),
            "class": kind.replace("`", ""),
            "complexity": complexity,
            "status": status,
            "proof": proof.replace("`", ""),
        })
    assert len(rows) == 42, len(rows)
    return rows


def embedded(title: str, path: Path, language: str = "text") -> str:
    return (
        f"\n\n# {title}\n\n"
        f"Источник: `{path.relative_to(ROOT)}`\n\n"
        f"~~~~{language}\n{path.read_text(errors='replace').rstrip()}\n~~~~\n"
    )


def main() -> None:
    for d in (OUT, RAW, EV, PATCHES, TOOLS, IMAGES):
        d.mkdir(parents=True, exist_ok=True)

    report_path = ROOT / "CyberSafe_report.md"
    report = report_path.read_text()
    methods = parse_attack_catalog(report)

    initial_flash = ROOT / "evidence/reproduction-final/flash.bin"
    latest_flash = ROOT / "evidence/manual-button-20260927/flash.bin"
    initial = initial_flash.read_bytes()
    latest = latest_flash.read_bytes()
    assert len(initial) == len(latest) == 0x200000
    assert initial[:0x100000] == latest[:0x100000]

    firmware = initial[:0x100000]
    (RAW / "firmware-first-1MiB.bin").write_bytes(firmware)
    copy(initial_flash, RAW / "flash-initial-2MiB.bin")
    copy(latest_flash, RAW / "flash-after-normal-mount-2MiB.bin")
    copy(ROOT / "evidence/reproduction-final/disk-region.bin", RAW / "disk-region-encoded-1MiB.bin")
    copy(ROOT / "evidence/reproduction-final/pin.bin", RAW / "pin.bin")
    copy(ROOT / "evidence/sram-read.bin", RAW / "sram-after-bootsel.bin")

    firmware_o = Path("/Users/ilinivan/cybersafe-research/firmware.o")
    disassembly = subprocess.run(
        ["objdump", "-d", str(firmware_o)], check=True, text=True, capture_output=True
    ).stdout
    (OUT / "firmware-full-disassembly.txt").write_text(disassembly)

    strings = printable_strings(firmware)
    (OUT / "firmware-strings.tsv").write_text(
        "offset_hex\tstring\n" + "\n".join(f"0x{o:x}\t{s}" for o, s in strings) + "\n"
    )

    ranges = [
        ("boot_and_vectors", 0x0000, 0x0200),
        ("disk_transform", 0x0300, 0x0450),
        ("main_and_password_call", 0x0800, 0x0900),
        ("password_function", 0x0AB0, 0x0E20),
        ("rgb_status_function", 0x1200, 0x1270),
        ("delay_function", 0x239C, 0x2490),
        ("usb_strings_and_pin", 0x5300, 0x5560),
    ]
    key_hex = []
    for name, start, end in ranges:
        key_hex.append(f"===== {name}: flash offsets 0x{start:x}..0x{end - 1:x} =====")
        key_hex.append(hex_dump(firmware[start:end], start))
    (OUT / "firmware-key-regions-hexdump.txt").write_text("\n\n".join(key_hex) + "\n")

    evidence_files = [
        "README.txt",
        "proof-summary.json",
        "firmware-analysis.json",
        "disassembly-proof.txt",
        "password-routine-disassembly.txt",
        "normal-unlock-proof.txt",
        "final-device-state.txt",
        "ram-exec-proof.json",
        "sram-read.bin.json",
        "fat-root-metadata.json",
        "disk-from-region.img.json",
        "disk-repeat.img.json",
        "uf2-validation.txt",
        "final-validation.json",
        "transform/transform-proof.json",
        "manual-button-20260927/README.txt",
        "manual-button-20260927/01-before-boot.txt",
        "manual-button-20260927/02-button-transition.txt",
        "manual-button-20260927/03-after-bootsel.txt",
        "manual-button-20260927/session.log",
        "manual-button-20260927/compare-with-initial.json",
        "manual-button-20260927/fat-root.json",
        "manual-button-20260927/firmware-analysis.json",
        "live-pin-0000-20260927/03-patch-write.txt",
        "live-pin-0000-20260927/04-unlock-0000-usb.txt",
        "live-pin-0000-20260927/05-pin-0000-success.txt",
        "live-pin-0000-20260927/07-restore-bootsel.txt",
        "live-pin-0000-20260927/08-restore-write.txt",
        "live-pin-0000-20260927/09-after-restore-before-pin.txt",
        "live-pin-0000-20260927/10-operator-confirmation.txt",
        "live-pin-0000-20260927/result.json",
        "live-no-lockout-20260927/session.txt",
        "live-no-lockout-20260927/ioreg-after-success.txt",
        "live-no-lockout-20260927/mount-after-success.txt",
        "live-no-lockout-20260927/result.json",
        "timing-camera-20260927/README.txt",
        "timing-camera-20260927/result.json",
        "organizer-qa-notes-20260927.md",
        "PROOF_INDEX.md",
        "proof-matrix.json",
        "METHOD_PROOF_MATRIX.md",
        "method-proof-matrix.json",
        "final-audit-20260927/00-timestamp.txt",
        "final-audit-20260927/01-system-profiler.txt",
        "final-audit-20260927/02-ioreg.txt",
        "final-audit-20260927/03-mount.txt",
        "final-audit-20260927/README.txt",
        "final-audit-20260927/result.json",
    ]
    for rel in evidence_files:
        copy(ROOT / "evidence" / rel, EV / rel)

    for src in (ROOT / "evidence/patches").iterdir():
        if src.is_file():
            copy(src, PATCHES / src.name)

    for src in (ROOT / "tools").iterdir():
        if src.is_file() and src.suffix in {".py", ".txt", ".S"}:
            copy(src, TOOLS / src.name)
    copy(ROOT / "reproduce_readonly.sh", TOOLS / "reproduce_readonly.sh")

    copy(ROOT / "images/board-from-task.png", IMAGES / "board.png")
    copy(ROOT / "images/memory-map.png", IMAGES / "memory-map.png")
    copy(ROOT / "images/attack-chain.png", IMAGES / "attack-chain.png")
    copy(ROOT / "task-requirements.txt", OUT / "task-requirements.txt")
    copy(report_path, OUT / "CyberSafe_report.md")

    facts = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "Передача контекста другой LLM без физического доступа к учебной плате",
        "scope": {
            "device": "собственная плата участника учебного хакатона ЛЦТ 2026",
            "case": "CyberSafe / Positive Technologies",
            "zip_opened": False,
            "zip_copied_as_a_file": False,
            "zip_extracted": False,
            "decoded_fat_metadata_only": True,
        },
        "confidence_legend": {
            "A": "воспроизведено на живой плате",
            "B": "доказано дампом, дизассемблированием или готовым артефактом",
            "C": "обоснованный план, но нужен прибор, сборка или живой тест",
            "N": "проверено, полезного результата нет",
        },
        "organizer_qa": {
            "source": "participant-provided meeting summary, not a verbatim transcript",
            "scoring_unit": "unique root attack vector, not another tool for the same method",
            "device_specific_proof_required": True,
            "ai_allowed_but_participant_must_understand": True,
            "writeup_format_free": True,
            "zip_yourprice_is_out_of_scope_easter_egg": True,
            "single_board_no_replacement_if_damaged": True,
            "final_recording": "ordinary smartphone on tripod",
        },
        "scoring_view": {
            "catalog_variants": 42,
            "report_families": 12,
            "conservative_confirmed_classes": [
                "unauthenticated ROM flash read",
                "plaintext PIN storage",
                "fixed XOR without device key or integrity",
                "unsigned firmware update",
            ],
            "partial_or_primitive_only": [
                "no PIN attempt lockout: ten errors checked, full sweep not run",
                "pre-auth SRAM execution: marker worked, storage dumper incomplete",
            ],
        },
        "hardware": {
            "mcu": "RP2040",
            "external_flash_bytes": 2097152,
            "mechanical_encoder": {"phase_a_gpio": 29, "phase_b_gpio": 27, "button_gpio": 28},
            "digit_ring_gpio_order_for_digits_0_to_9": [7, 6, 5, 4, 3, 2, 1, 0, 9, 8],
            "code_position_led_gpios": [13, 12, 11, 10],
            "rgb_status_led": {
                "implementation": "PIO-driven 24-bit RGB function at flash offset 0x1218",
                "wrong_pin": "red (32,0,0), three 200 ms on/off cycles",
                "correct_pin": "green (0,32,0)",
            },
            "buttons": ["BOOT", "RESET", "encoder push"],
        },
        "usb": {
            "application": {"vid_pid": "cafe:4000", "name": "RP2040 Flash MSC", "manufacturer": "PositiveLabs", "serial": "123456", "volume": "NO NAME"},
            "rom_bootsel": {"vid_pid": "2e8a:0003", "name": "RP2 Boot", "manufacturer": "Raspberry Pi", "serial": "E0C9125B0D9B", "volume": "RPI-RP2", "uf2": "UF2 Bootloader v3.0"},
            "state_machine": [
                "После RESET основная прошивка ждёт PIN и до успеха не поднимает USB MSC.",
                "Правильный PIN возвращает из функции проверки; после этого инициализируется cafe:4000.",
                "BOOT удерживается во время RESET: запускается ROM BOOTSEL 2e8a:0003 без проверки PIN.",
            ],
        },
        "memory_map": {
            "xip_base": "0x10000000",
            "firmware_flash_offsets": "0x000000..0x0fffff",
            "encoded_disk_flash_offsets": "0x100000..0x1fffff",
            "encoded_disk_xip": "0x10100000..0x101fffff",
            "pin_flash_offset": "0x5500",
            "pin_xip_address": "0x10005500",
            "password_function_offset": "0xab0",
            "password_call_offset": "0x8a6",
            "usb_init_continues_offset": "0x8aa",
            "comparison_offset": "0xc8a",
            "conditional_branch_offset": "0xc8c",
            "failure_offset": "0xcd4",
            "success_offset": "0xc9a",
            "success_flag_sram": "0x20002ed2",
        },
        "secrets": {
            "pin": "8170",
            "pin_raw_hex": "08 01 07 00",
            "pin_storage": "четыре открытых байта во внешней flash",
        },
        "pin_timing": {
            "algorithm": "сравнение слева направо, выход на первой ошибке",
            "delay_after_each_matching_digit_ms": 50,
            "evidence": "CMP 0xc8a; BNE 0xc8c; MOVS r0,#50 0xc8e; call 0x239c",
            "camera_240fps_expected_frames_per_step": 12,
            "physical_camera_test_completed": True,
            "physical_camera_result": "negative: blue changed to red without a usable visible timing difference",
            "pin_recovered_by_camera": False,
        },
        "disk_transform": {
            "kind": "фиксированный обратимый XOR-поток",
            "uses_pin": False,
            "uses_unique_chip_id": False,
            "has_nonce": False,
            "has_integrity_or_mac": False,
            "source_flash_offset": "0x100000",
            "source_xip_address": "0x10100000",
            "size_bytes": 1048576,
            "sector_step": "0x38c9cda0",
            "initial_state": "0x9e37a9ea",
            "block_step": "0x41c64e6d",
            "golden_ratio": "0x9e3779b1",
            "decoded_filesystem": "FAT12",
            "boot_signature": "55aa",
        },
        "hashes": {
            "initial_flash_2MiB": sha256(initial_flash),
            "latest_flash_2MiB": sha256(latest_flash),
            "firmware_first_1MiB": sha256(RAW / "firmware-first-1MiB.bin"),
            "pin_bin": sha256(ROOT / "evidence/reproduction-final/pin.bin"),
            "initial_encoded_disk": sha256(ROOT / "evidence/reproduction-final/disk-region.bin"),
        },
        "verified_live": [
            "Полное PICOBOOT-чтение flash без ввода PIN, два чтения совпали.",
            "Точечное чтение PIN 8170 по адресу 0x10005500.",
            "Чтение закодированной области диска 0x10100000 размером 1 МиБ.",
            "Штатное открытие cafe:4000 / NO NAME после ввода 8170.",
            "PICOBOOT PC_WRITE + PC_EXEC в SRAM и восстановление исходных байтов RAM.",
            "Ручной переход PositiveLabs cafe:4000 -> RP2 Boot 2e8a:0003 кнопками BOOT+RESET.",
            "M20: PIN временно заменён с 8170 на 0000, PIN 0000 поднял cafe:4000 / NO NAME, затем исходный сектор записан обратно.",
            "Частичная M12: после десяти неверных попыток по инструкции плата приняла 8170 и создала новый USB-сеанс; полный перебор не выполнялся.",
        ],
        "verified_offline": [
            "PIN хранится открытыми цифрами.",
            "Область диска декодируется до валидного FAT12.",
            "Прямое чтение области и извлечение из полного дампа независимо дают один и тот же декодированный FAT12 SHA-256.",
            "Повторное кодирование совпадает с исходным шифротекстом.",
            "Known plaintext восстанавливает байты XOR-потока на известных позициях; полная расшифровка использует константы из прошивки.",
            "Шифротекст изменяем без MAC: метка NO NAME -> HACKATHON в копии сектора.",
            "M17–M19 собраны в валидные UF2 и проверены статически; M20 отдельно проверен на железе.",
            "В машинном коде есть ранний выход сравнения и sleep_ms(50) после совпавшей цифры.",
        ],
        "negative_or_incomplete": [
            "Timing-опыт камерой 240 FPS выполнен: пригодной разницы не видно, PIN этим способом не получен.",
            "После входа в BOOTSEL SRAM прочитана; PIN, FAT12, MSDOS5.0 и полезный plaintext не найдены.",
            "Полный RAM-only дампер/дешифратор не закончен.",
            "SWD, внешний SPI/QSPI, электрический timing, fault injection и патчи M17–M19 ещё не проверены на железе.",
            "picotool на этом ноутбуке не устанавливался; использован собственный read-only клиент.",
        ],
        "artifacts": {
            "attack_catalog": "ATTACK_CATALOG.json",
            "proof_matrix": "evidence/proof-matrix.json",
            "method_proof_matrix": "evidence/method-proof-matrix.json",
            "proof_index": "evidence/PROOF_INDEX.md",
            "full_context": "FULL_CONTEXT.md",
            "full_disassembly": "firmware-full-disassembly.txt",
            "firmware_strings": "firmware-strings.tsv",
            "raw_data": "raw/",
            "proofs": "evidence/",
            "patches": "patches/",
            "tools": "tools/",
        },
    }
    (OUT / "FACTS.json").write_text(json.dumps(facts, ensure_ascii=False, indent=2) + "\n")
    (OUT / "ATTACK_CATALOG.json").write_text(
        json.dumps({"count": len(methods), "methods": methods}, ensure_ascii=False, indent=2) + "\n"
    )

    readme = """# CyberSafe: пакет контекста для другой LLM

Пакет собран по собственной учебной плате хакатона ЛЦТ 2026. Он нужен для анализа без физического доступа к устройству.

## С чего начать

1. `FULL_CONTEXT.md` — единый текст для загрузки в LLM.
2. `FACTS.json` — короткие проверенные факты и границы уверенности.
3. `ATTACK_CATALOG.json` — 42 варианта внутри 12 корневых векторов, со статусами A/B/C/N.
4. `firmware-full-disassembly.txt` и `firmware-strings.tsv` — материал для нового реверса.
5. `raw/firmware-first-1MiB.bin` — прошивка без второй половины flash, где лежит пользовательский диск.
6. `evidence/` — логи и JSON реальных прогонов.
7. `patches/` и `tools/` — готовые артефакты и воспроизводящие скрипты.

## Статусы

- A: реально выполнено на плате.
- B: доказано дампом, дизассемблированием или готовым файлом.
- C: обоснованный способ, но живого теста нет.
- N: проверено, полезного результата нет.

Не выдавать C за выполненную атаку. Задержка 50 мс подтверждена машинным кодом, но живой опыт камерой 240 FPS дал отрицательный результат: пригодной разницы не видно. M20 с PIN 0000 проверен на плате и восстановлен; M17–M19 валидны статически, но не запускались. Для M12 проверены десять ошибок и последующий вход, полный перебор 10 000 PIN не выполнялся.

## Ограничение по данным

В FAT найден ZIP-файл, но его содержимое не открывалось, не копировалось отдельным файлом и не распаковывалось. В пакет не включён декодированный FAT-образ. Приложены только исходные raw-дампы и метаданные файловой системы.

## Целостность

`SHA256SUMS.txt` содержит контрольные суммы всех файлов пакета, кроме самого списка.
"""
    (OUT / "README.md").write_text(readme)

    prompt = """# Задание для следующей LLM

Ты анализируешь собственную учебную плату участника хакатона CyberSafe / ЛЦТ 2026. Физического доступа к плате у тебя нет. Используй приложенные дампы, дизассемблирование, логи и исходники.

Правила ответа:

1. Разделяй наблюдаемый факт, вывод из машинного кода и пока не проверенную гипотезу.
2. Для каждого нового способа укажи корневую причину, необходимые условия, пошаговую проверку, ожидаемый сигнал успеха, риск для платы и способ возврата.
3. Не считай разные команды одного и того же примитива независимыми уязвимостями без объяснения.
4. Не утверждай, что SWD, SPI/QSPI, электрический timing, fault injection или патчи M17–M19 уже выполнены. Камера 240 FPS выполнена с отрицательным результатом. M20 выполнен и восстановлен; смотри его живой лог.
5. Не открывай и не анализируй содержимое ZIP внутри пользовательского диска. Оно не относится к задаче.
6. Сначала изучи FACTS.json, ATTACK_CATALOG.json и evidence/*. Затем при необходимости используй полный дизассемблерный листинг и raw firmware.

Полезные направления для продолжения:

- восстановить более полный call graph и дать имена функциям Pico SDK/TinyUSB;
- проверить, есть ли другие пути до USB init кроме функции PIN;
- найти все чтения адреса 0x10005500 и записи флага 0x20002ed2;
- проверить наличие командного протокола, vendor endpoints, CDC/HID или скрытых USB-дескрипторов;
- поискать дополнительные секреты и тестовые режимы только в первом 1 МиБ firmware;
- подтвердить или опровергнуть возможность SWD без пайки по фотографии/разводке;
- предложить минимальный безопасный live-тест каждого готового UF2 с точным восстановлением;
- для timing oracle рассматривать фотодиод, токовый шунт или логический анализатор: обычная камера 240 FPS уже дала отрицательный результат;
- оценить чтение QSPI прищепкой, пассивный сниффинг, clock/power glitch и EMFI;
- найти способы получить данные, которые ещё не представлены среди M01–M42.

Начни с краткого списка новых гипотез, затем подробно разбери самые реалистичные и укажи, какие файлы пакета подтверждают каждый вывод.
"""
    (OUT / "PROMPT_FOR_NEXT_LLM.md").write_text(prompt)

    context = """# CyberSafe / ЛЦТ 2026 — полный текстовый контекст

Этот файл можно целиком передать модели, у которой нет доступа к плате. Бинарные файлы и полный листинг лежат рядом и перечислены в `ARTIFACT_MANIFEST.json`.

Коротко: RP2040, внешняя flash 2 МиБ, PIN 8170, ROM BOOTSEL читает flash без аутентификации, пользовательский диск занимает второй 1 МиБ и защищён фиксированным XOR без PIN и MAC.
"""
    context += embedded("Инструкция следующей модели", OUT / "PROMPT_FOR_NEXT_LLM.md", "markdown")
    context += embedded("Проверенные факты", OUT / "FACTS.json", "json")
    context += embedded("Каталог 42 вариантов в 12 векторах", OUT / "ATTACK_CATALOG.json", "json")
    context += embedded("Текст ТЗ", OUT / "task-requirements.txt")
    context += embedded("Основной отчёт", OUT / "CyberSafe_report.md", "markdown")
    context += embedded("Сводка доказательств", EV / "proof-summary.json", "json")
    context += embedded("Разбор прошивки", EV / "firmware-analysis.json", "json")
    context += embedded("Критическое дизассемблирование", EV / "disassembly-proof.txt")
    context += embedded("Полная функция проверки PIN", EV / "password-routine-disassembly.txt")
    context += embedded("Проверка преобразования диска", EV / "transform/transform-proof.json", "json")
    context += embedded("Перекрёстная проверка двух путей декодирования: прямой диапазон", EV / "disk-from-region.img.json", "json")
    context += embedded("Перекрёстная проверка двух путей декодирования: полный дамп", EV / "disk-repeat.img.json", "json")
    context += embedded("Выполнение кода в SRAM", EV / "ram-exec-proof.json", "json")
    context += embedded("Манифест патчей", PATCHES / "patch-manifest.json", "json")
    context += embedded("Обратная проверка патчей и restore UF2", PATCHES / "roundtrip-proof.json", "json")
    context += embedded("Ручной BOOT+RESET", EV / "manual-button-20260927/README.txt")
    context += embedded("Лог ручного переключения", EV / "manual-button-20260927/02-button-transition.txt")
    context += embedded("Сравнение двух дампов", EV / "manual-button-20260927/compare-with-initial.json", "json")
    context += embedded("Штатное открытие после PIN", EV / "normal-unlock-proof.txt")
    context += embedded("Живой патч PIN 0000", EV / "live-pin-0000-20260927/result.json", "json")
    context += embedded("Частичная проверка отсутствия блокировки", EV / "live-no-lockout-20260927/result.json", "json")
    context += embedded("Отрицательный timing-опыт камерой", EV / "timing-camera-20260927/result.json", "json")
    context += embedded("Конспект Q&A организаторов", EV / "organizer-qa-notes-20260927.md", "markdown")
    context += embedded("Матрица доказательств", EV / "proof-matrix.json", "json")
    context += embedded("Аудит пруфов для M01-M42", EV / "method-proof-matrix.json", "json")
    context += embedded("Финальный контроль состояния платы", EV / "final-audit-20260927/result.json", "json")
    context += embedded("Строки прошивки с адресами", OUT / "firmware-strings.tsv")
    context += embedded("Hex ключевых участков", OUT / "firmware-key-regions-hexdump.txt")
    for name in [
        "read_picoboot.py",
        "analyze_firmware.py",
        "decode_disk_region.py",
        "inspect_fat_root.py",
        "prove_transform.py",
        "picoboot_ram_exec_probe.py",
        "make_patch_artifacts.py",
    ]:
        context += embedded(f"Исходник {name}", TOOLS / name, "python")
    (OUT / "FULL_CONTEXT.md").write_text(context)

    descriptions = {
        "FULL_CONTEXT.md": "Самодостаточный текст для передачи LLM",
        "FACTS.json": "Структурированные факты, статусы и ограничения",
        "ATTACK_CATALOG.json": "42 варианта реализации внутри 12 корневых векторов",
        "firmware-full-disassembly.txt": "Полный objdump синтетического ELF прошивки",
        "firmware-strings.tsv": "ASCII-строки только из первого 1 МиБ firmware",
        "firmware-key-regions-hexdump.txt": "Hex критических областей с адресами",
        "raw/firmware-first-1MiB.bin": "Прошивка без области пользовательского диска",
        "raw/flash-initial-2MiB.bin": "Первый полный raw-дамп flash",
        "raw/flash-after-normal-mount-2MiB.bin": "Повторный raw-дамп после штатного монтирования",
        "raw/disk-region-encoded-1MiB.bin": "Закодированная область диска; ZIP не извлекался",
        "raw/sram-after-bootsel.bin": "SRAM после RESET в BOOTSEL, отрицательный memory-forensics опыт",
    }
    manifest_entries = []
    for p in sorted(x for x in OUT.rglob("*") if x.is_file() and x.name not in {"ARTIFACT_MANIFEST.json", "SHA256SUMS.txt"}):
        rel = str(p.relative_to(OUT))
        manifest_entries.append({
            "path": rel,
            "size_bytes": p.stat().st_size,
            "sha256": sha256(p),
            "description": descriptions.get(rel, "Вспомогательный файл пакета"),
        })
    manifest = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "file_count_excluding_manifest_and_checksums": len(manifest_entries),
        "files": manifest_entries,
    }
    (OUT / "ARTIFACT_MANIFEST.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")

    checksum_files = sorted(p for p in OUT.rglob("*") if p.is_file() and p.name != "SHA256SUMS.txt")
    (OUT / "SHA256SUMS.txt").write_text(
        "\n".join(f"{sha256(p)}  {p.relative_to(OUT)}" for p in checksum_files) + "\n"
    )
    print(json.dumps({
        "output": str(OUT),
        "files": len(checksum_files),
        "bytes": sum(p.stat().st_size for p in checksum_files),
        "methods": len(methods),
        "full_context_bytes": (OUT / "FULL_CONTEXT.md").stat().st_size,
        "zip_files": [str(p) for p in OUT.rglob("*.zip")],
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
