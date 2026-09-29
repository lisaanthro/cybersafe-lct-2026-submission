#!/usr/bin/env python3
"""Build a machine-readable and human-readable index of CyberSafe proofs."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


STAGES = [
    {
        "id": "P01",
        "claim": "Кнопки BOOT+RESET переводят выданную плату из PositiveLabs cafe:4000 в ROM RP2 Boot 2e8a:0003.",
        "status": "A",
        "artifacts": [
            "manual-button-20260927/01-before-boot.txt",
            "manual-button-20260927/02-button-transition.txt",
            "manual-button-20260927/03-after-bootsel.txt",
        ],
        "limit": None,
    },
    {
        "id": "P02",
        "claim": "Вся внешняя flash размером 2 МиБ читается без ввода PIN; два чтения совпадают.",
        "status": "A",
        "artifacts": [
            "reproduction-final/flash.bin",
            "reproduction-final/flash.bin.json",
            "reproduction-final/session.log",
            "manual-button-20260927/flash.bin.json",
            "manual-button-20260927/compare-with-initial.json",
        ],
        "limit": None,
    },
    {
        "id": "P03",
        "claim": "Четыре байта 08 01 07 00 читаются напрямую по 0x10005500 и дают PIN 8170.",
        "status": "A",
        "artifacts": [
            "reproduction-final/pin.bin",
            "reproduction-final/pin.bin.json",
            "manual-button-20260927/pin.bin.json",
            "firmware-analysis.json",
        ],
        "limit": None,
    },
    {
        "id": "P04",
        "claim": "Закодированная область хранилища размером 1 МиБ читается напрямую по 0x10100000.",
        "status": "A",
        "artifacts": [
            "reproduction-final/disk-region.bin",
            "reproduction-final/disk-region.bin.json",
            "manual-button-20260927/disk-region.bin.json",
        ],
        "limit": None,
    },
    {
        "id": "P05",
        "claim": "Фиксированное XOR-преобразование восстанавливает корректный FAT12; прямое чтение области и извлечение из полного дампа дают одинаковый образ, а обратное кодирование совпадает с исходным шифротекстом.",
        "status": "B",
        "artifacts": [
            "reproduction-final/disk.img",
            "reproduction-final/disk.img.json",
            "reproduction-final/fat-root.json",
            "transform/transform-proof.json",
            "disk-region-direct.bin",
            "disk-region-direct.bin.json",
            "disk-from-region.img",
            "disk-from-region.img.json",
            "flash-read-repeat.bin",
            "flash-read-repeat.bin.json",
            "disk-repeat.img",
            "disk-repeat.img.json",
            "fat-root-metadata.json",
        ],
        "limit": "Проверены файловая система и метаданные. Содержимое файла-пасхалки не читалось.",
    },
    {
        "id": "P06",
        "claim": "Найденный PIN 8170 штатно включает USB Mass Storage cafe:4000 и том NO NAME.",
        "status": "A",
        "artifacts": ["normal-unlock-proof.txt", "final-device-state.txt"],
        "limit": None,
    },
    {
        "id": "P07",
        "claim": "PICOBOOT PC_WRITE и PC_EXEC выполняют загруженный код в SRAM, маркер 0xc0dec0de прочитан обратно.",
        "status": "A",
        "artifacts": ["ram-exec-proof.json"],
        "limit": "Доказан примитив выполнения кода; полный RAM-only дампер данных не закончен.",
    },
    {
        "id": "P08",
        "claim": "Точечная UF2-замена PIN 8170 на 0000 принята платой; 0000 включает cafe:4000 и NO NAME; затем исходный сектор записан обратно.",
        "status": "A",
        "artifacts": [
            "live-pin-0000-20260927/result.json",
            "live-pin-0000-20260927/03-patch-write.txt",
            "live-pin-0000-20260927/04-unlock-0000-usb.txt",
            "live-pin-0000-20260927/05-pin-0000-success.txt",
            "live-pin-0000-20260927/07-restore-bootsel.txt",
            "live-pin-0000-20260927/08-restore-write.txt",
            "live-pin-0000-20260927/10-operator-confirmation.txt",
            "patches/pin-0000.uf2",
            "patches/restore-sector-005000.uf2",
        ],
        "limit": "Возврат исходного PIN подтверждён оператором и последующим штатным USB; отдельного электрического счётчика нажатий не было.",
    },
    {
        "id": "P09",
        "claim": "После серии из десяти неверных попыток по инструкции плата приняла 8170 и создала новый USB-сеанс.",
        "status": "C-partial-live",
        "artifacts": [
            "live-no-lockout-20260927/result.json",
            "live-no-lockout-20260927/session.txt",
            "live-no-lockout-20260927/ioreg-after-success.txt",
        ],
        "limit": "Хост подтверждает новый USB session ID, но отдельные нажатия не считались электрически; все 10 000 PIN не перебирались.",
    },
    {
        "id": "P10",
        "claim": "В прошивке есть ранний выход и sleep_ms(50), но камера 240 FPS не дала пригодного timing-сигнала.",
        "status": "N",
        "artifacts": [
            "password-routine-disassembly.txt",
            "timing-camera-20260927/README.txt",
            "timing-camera-20260927/result.json",
        ],
        "limit": "Исходное видео в пакет не передано; сохранено наблюдение оператора. Электрическое измерение не выполнялось.",
    },
    {
        "id": "P11",
        "claim": "Готовые патчи M17-M19 меняют только заявленные инструкции и собраны в валидные UF2.",
        "status": "B",
        "artifacts": [
            "patches/patch-manifest.json",
            "patches/roundtrip-proof.json",
            "uf2-validation.txt",
            "disassembly-proof.txt",
            "patches/bypass-compare.uf2",
            "patches/skip-password-call.uf2",
            "patches/return-from-password.uf2",
        ],
        "limit": "M17-M19 на плату не записывались и отдельными корневыми векторами не считаются.",
    },
    {
        "id": "P12",
        "claim": "Чтение SRAM после RESET/BOOTSEL не нашло полезного plaintext.",
        "status": "N",
        "artifacts": ["sram-read.bin", "sram-read.bin.json"],
        "limit": "RESET уничтожает нужный контекст; для чтения без RESET нужен SWD.",
    },
    {
        "id": "P13",
        "claim": "Для возврата подготовлен полный UF2 исходной flash и отдельные исходные секторы; UF2 структурно проверены.",
        "status": "B",
        "artifacts": [
            "restore-full-original.uf2",
            "restore-full-original.json",
            "patches/restore-sector-000000.uf2",
            "patches/restore-sector-005000.uf2",
            "patches/patch-manifest.json",
            "patches/roundtrip-proof.json",
            "uf2-validation.txt",
        ],
        "limit": "Полный 2 МиБ UF2 не требовалось записывать; в M20 на плате проверена запись точечного восстановительного сектора.",
    },
    {
        "id": "P14",
        "claim": "После экспериментов плата осталась рабочей: после полного переподключения PIN 8170 запускал штатный USB, а финальный read-only снимок снова видит PositiveLabs cafe:4000.",
        "status": "A",
        "artifacts": [
            "final-device-state.txt",
            "final-audit-20260927/00-timestamp.txt",
            "final-audit-20260927/01-system-profiler.txt",
            "final-audit-20260927/02-ioreg.txt",
            "final-audit-20260927/03-mount.txt",
            "final-audit-20260927/README.txt",
            "final-audit-20260927/result.json",
        ],
        "limit": "В финальном снимке USB-сеанс уже существовал и том не был смонтирован; сам ввод 8170 после полного переподключения зафиксирован отдельным логом.",
    },
]


VECTORS = [
    ("V-01", "ROM BOOTSEL читает flash до PIN", "A", ["P01", "P02", "P03", "P04"]),
    ("V-02", "PIN хранится открытыми цифрами", "A/B", ["P03", "P06"]),
    ("V-03", "Фиксированный XOR без ключа и MAC", "B", ["P04", "P05"]),
    ("V-04", "Нет блокировки попыток и есть ранний выход сравнения", "partial/N", ["P09", "P10"]),
    ("V-05", "Выполнение кода из SRAM до PIN", "A primitive", ["P07"]),
    ("V-06", "Нет проверки подписи обновления", "A/B", ["P08", "P11"]),
    ("V-07", "Физически доступные ввод и индикация", "C", []),
    ("V-08", "Доступ к SWD", "C", []),
    ("V-09", "Внешняя QSPI flash", "C", []),
    ("V-10", "Обычный USB MSC после компрометации PIN", "A", ["P06"]),
    ("V-11", "Fault injection", "C", []),
    ("V-12", "Forensics образа и SRAM", "C/N", ["P12"]),
]


def main() -> None:
    referenced = sorted({item for stage in STAGES for item in stage["artifacts"]})
    files = {}
    for rel in referenced:
        path = EVIDENCE / rel
        if not path.is_file():
            raise SystemExit(f"missing proof artifact: {path}")
        files[rel] = {"size_bytes": path.stat().st_size, "sha256": sha256(path)}

    result = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "device": "CyberSafe / Positive Technologies / ЛЦТ 2026",
        "status_legend": {
            "A": "живой результат на выданной плате",
            "B": "статический или офлайн-результат на дампе этой платы",
            "C": "план без полного живого результата",
            "N": "проверено, полезный результат не получен",
        },
        "scope": {
            "zip_easter_egg_opened": False,
            "zip_easter_egg_copied": False,
            "zip_easter_egg_extracted": False,
        },
        "stages": STAGES,
        "root_vectors": [
            {"id": vector, "root_cause": cause, "status": status, "proof_stages": proofs}
            for vector, cause, status, proofs in VECTORS
        ],
        "artifact_files": files,
    }
    (EVIDENCE / "proof-matrix.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")

    lines = [
        "# Индекс доказательств CyberSafe",
        "",
        "Этот файл связывает каждое утверждение с конкретными артефактами. Статус C не выдаётся за выполненную атаку, статус N сохраняет отрицательный результат.",
        "",
        "## Этапы",
        "",
        "| Этап | Статус | Что доказано | Ограничение |",
        "|---|---|---|---|",
    ]
    for stage in STAGES:
        limitation = stage["limit"] or "—"
        lines.append(f"| {stage['id']} | {stage['status']} | {stage['claim']} | {limitation} |")
    lines += ["", "## Файлы и SHA-256", ""]
    for rel, info in files.items():
        lines.append(f"- `{rel}` — {info['size_bytes']} байт, `{info['sha256']}`")
    lines += [
        "",
        "ZIP-пасхалка не открывалась, не копировалась отдельным файлом и не распаковывалась.",
    ]
    (EVIDENCE / "PROOF_INDEX.md").write_text("\n".join(lines) + "\n")
    print(json.dumps({"stages": len(STAGES), "vectors": len(VECTORS), "artifacts": len(files)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
