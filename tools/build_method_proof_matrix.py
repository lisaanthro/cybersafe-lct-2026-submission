#!/usr/bin/env python3
"""Build an honest proof map for every M01..M42 report variant."""

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


def parse_methods(report: str) -> list[dict]:
    methods = []
    for line in report.splitlines():
        if not line.startswith("| M"):
            continue
        cols = [part.strip() for part in line.strip().strip("|").split("|")]
        if len(cols) != 6:
            continue
        method_id, method, kind, complexity, report_status, proof = cols
        methods.append(
            {
                "id": method_id,
                "method": method.replace("`", ""),
                "class": kind.replace("`", ""),
                "complexity": complexity,
                "report_status": report_status,
                "report_proof_cell": proof.replace("`", ""),
            }
        )
    if [item["id"] for item in methods] != [f"M{i:02d}" for i in range(1, 43)]:
        raise SystemExit("report method table is incomplete or out of order")
    return methods


def vector_for(number: int) -> str:
    if 1 <= number <= 4:
        return "V-01"
    if 5 <= number <= 6:
        return "V-02"
    if 7 <= number <= 10:
        return "V-03"
    if 11 <= number <= 14:
        return "V-04"
    if 15 <= number <= 16:
        return "V-05"
    if 17 <= number <= 22:
        return "V-06"
    if number in {23, 24, 25, 42}:
        return "V-07"
    if 26 <= number <= 28:
        return "V-08"
    if 29 <= number <= 32:
        return "V-09"
    if 33 <= number <= 34:
        return "V-10"
    if number in {35, 36, 37, 38, 41}:
        return "V-11"
    if number in {39, 40}:
        return "V-12"
    raise ValueError(number)


ARTIFACTS = {
    "M01": [
        "evidence/reproduction-final/session.log",
        "evidence/reproduction-final/flash.bin.json",
        "evidence/manual-button-20260927/session.log",
        "evidence/manual-button-20260927/compare-with-initial.json",
    ],
    "M02": [
        "evidence/reproduction-final/disk-region.bin.json",
        "evidence/manual-button-20260927/disk-region.bin.json",
    ],
    "M03": [
        "evidence/reproduction-final/pin.bin.json",
        "evidence/manual-button-20260927/pin.bin.json",
    ],
    "M04": [],
    "M05": [
        "evidence/reproduction-final/firmware-analysis.json",
        "evidence/password-routine-disassembly.txt",
    ],
    "M06": ["evidence/normal-unlock-proof.txt", "evidence/final-device-state.txt"],
    "M07": [
        "evidence/reproduction-final/disk.img.json",
        "evidence/reproduction-final/fat-root.json",
        "evidence/disk-from-region.img.json",
        "evidence/disk-repeat.img.json",
        "evidence/fat-root-metadata.json",
    ],
    "M08": ["evidence/transform/transform-proof.json"],
    "M09": [
        "evidence/transform/transform-proof.json",
        "evidence/transform/sector0-label-modified-cipher.bin",
    ],
    "M10": ["evidence/transform/transform-proof.json"],
    "M11": [
        "evidence/password-routine-disassembly.txt",
        "evidence/timing-camera-20260927/README.txt",
        "evidence/timing-camera-20260927/result.json",
    ],
    "M12": [
        "evidence/live-no-lockout-20260927/result.json",
        "evidence/live-no-lockout-20260927/session.txt",
        "evidence/live-no-lockout-20260927/ioreg-after-success.txt",
    ],
    "M13": ["evidence/firmware-analysis.json"],
    "M14": ["evidence/password-routine-disassembly.txt", "evidence/timing-camera-20260927/result.json"],
    "M15": ["evidence/ram-exec-proof.json"],
    "M16": ["evidence/ram-exec-proof.json", "evidence/ram-sector-debug.bin.json"],
    "M17": [
        "evidence/patches/bypass-compare.uf2",
        "evidence/patches/patch-manifest.json",
        "evidence/patches/roundtrip-proof.json",
        "evidence/disassembly-proof.txt",
        "evidence/uf2-validation.txt",
    ],
    "M18": [
        "evidence/patches/skip-password-call.uf2",
        "evidence/patches/patch-manifest.json",
        "evidence/patches/roundtrip-proof.json",
        "evidence/disassembly-proof.txt",
        "evidence/uf2-validation.txt",
    ],
    "M19": [
        "evidence/patches/return-from-password.uf2",
        "evidence/patches/patch-manifest.json",
        "evidence/patches/roundtrip-proof.json",
        "evidence/disassembly-proof.txt",
        "evidence/uf2-validation.txt",
    ],
    "M20": [
        "evidence/patches/pin-0000.uf2",
        "evidence/patches/restore-sector-005000.uf2",
        "evidence/patches/roundtrip-proof.json",
        "evidence/live-pin-0000-20260927/result.json",
        "evidence/live-pin-0000-20260927/03-patch-write.txt",
        "evidence/live-pin-0000-20260927/05-pin-0000-success.txt",
        "evidence/live-pin-0000-20260927/08-restore-write.txt",
        "evidence/live-pin-0000-20260927/10-operator-confirmation.txt",
        "evidence/final-device-state.txt",
    ],
    "M21": [],
    "M22": [
        "evidence/restore-full-original.uf2",
        "evidence/restore-full-original.json",
        "evidence/patches/patch-manifest.json",
        "evidence/uf2-validation.txt",
    ],
    "M23": ["evidence/firmware-analysis.json"],
    "M24": ["evidence/firmware-analysis.json", "images/board-from-task.png"],
    "M25": ["evidence/firmware-analysis.json", "images/board-from-task.png"],
    "M26": ["images/board-from-task.png"],
    "M27": ["evidence/password-routine-disassembly.txt"],
    "M28": ["evidence/firmware-analysis.json", "evidence/sram-read.bin.json"],
    "M29": ["images/board-from-task.png", "evidence/reproduction-final/flash.bin.json"],
    "M30": ["images/board-from-task.png", "evidence/reproduction-final/flash.bin.json"],
    "M31": ["evidence/firmware-analysis.json", "evidence/reproduction-final/disk-region.bin.json"],
    "M32": ["evidence/patches/patch-manifest.json", "evidence/patches/roundtrip-proof.json"],
    "M33": [
        "evidence/normal-unlock-proof.txt",
        "evidence/final-device-state.txt",
        "evidence/final-audit-20260927/result.json",
    ],
    "M34": ["evidence/normal-unlock-proof.txt"],
    "M35": ["evidence/password-routine-disassembly.txt"],
    "M36": ["evidence/password-routine-disassembly.txt"],
    "M37": ["evidence/password-routine-disassembly.txt"],
    "M38": ["evidence/password-routine-disassembly.txt", "evidence/firmware-analysis.json"],
    "M39": ["evidence/fat-root-metadata.json", "evidence/organizer-qa-notes-20260927.md"],
    "M40": ["evidence/sram-read.bin", "evidence/sram-read.bin.json"],
    "M41": ["evidence/password-routine-disassembly.txt", "evidence/timing-camera-20260927/result.json"],
    "M42": ["evidence/firmware-analysis.json", "images/board-from-task.png"],
}


LIMITATIONS = {
    "M01": "Живой read-only дамп сделан дважды; пользовательский ZIP не открывался.",
    "M02": "Живое чтение диапазона сделано дважды; содержимое файлов не извлекалось.",
    "M03": "Четыре байта считаны без PIN и повторены в отдельной сессии.",
    "M04": "picotool на этом ноутбуке не установлен и команда не запускалась; это альтернативный клиент того же ROM-примитива.",
    "M05": "Статический анализ дампа; работоспособность найденного PIN отдельно подтверждена M06.",
    "M06": "PIN введён вручную; лог хоста видит USB и mount, но не электрические события энкодера.",
    "M07": "Два независимых пути дали одинаковый FAT12; содержимое ZIP не читалось.",
    "M08": "Known plaintext восстанавливает поток только на известных позициях; полный диск декодирован по алгоритму из прошивки.",
    "M09": "Направленная замена доказана на копии сектора; flash платы не менялась.",
    "M10": "Обратное кодирование совпало на этой плате; перенос на второй экземпляр не проверялся.",
    "M11": "Камера 240 FPS не дала различимого сигнала; PIN этим способом не получен.",
    "M12": "Проверены 10 заявленных ошибок и успешный вход; нажатия не считались электрически, диапазон 0000..9999 не пройден.",
    "M13": "GPIO найдены статически, второй МК к плате не подключался.",
    "M14": "Ранний выход и задержка есть в коде; электрический датчик и автомат ввода не собирались, камера дала отрицательный результат.",
    "M15": "Выполнен короткий маркерный payload и восстановлена SRAM; данные диска этим payload не снимались.",
    "M16": "Примитив M15 работает, но RAM-only копировщик сектора не закончен; отладочный опыт дал FF до снятия питания.",
    "M17": "Байты и UF2 проверены офлайн; на плату этот патч не записывался.",
    "M18": "Байты и UF2 проверены офлайн; на плату этот патч не записывался.",
    "M19": "Байты и UF2 проверены офлайн; на плату этот патч не записывался.",
    "M20": "PIN 0000 проверен на плате и сектор восстановлен; прямое чтение четырёх байтов после restore не выполнено, зато 8170 проверен после полного переподключения.",
    "M21": "Собственная MSC-прошивка не написана и не запускалась.",
    "M22": "Полный модифицированный образ не записывался; готовы точечные UF2 и полный UF2 возврата.",
    "M23": "Электрический автомат ввода не подключался; есть только статически найденные GPIO.",
    "M24": "Съёмка фактического ввода владельца не выполнялась; камера 240 FPS проверяла другой timing-сценарий M11 и там не сработала.",
    "M25": "Логический анализатор к линиям энкодера не подключался.",
    "M26": "SWD-точки и отсутствие защиты живым probe не проверялись.",
    "M27": "Адрес ветки известен, но остановка CPU и перенос PC через SWD не выполнялись.",
    "M28": "SRAM через SWD без reset не читалась; чтение после BOOTSEL дало отрицательный M40.",
    "M29": "Прищепка и внешний программатор не подключались; пригодность контактов in-circuit не проверена.",
    "M30": "Микросхема не выпаивалась; риск высокий, запасной платы нет.",
    "M31": "QSPI-трасса анализатором не снималась.",
    "M32": "Клон flash не устанавливался; готовые патчи проверены только как файлы, кроме M20.",
    "M33": "Штатный MSC подтверждён после PIN 8170; содержимое ZIP не открывалось.",
    "M34": "USB-трафик анализатором не записывался; есть только факт обычного MSC.",
    "M35": "Voltage glitch не выполнялся; окно известно только по машинному коду.",
    "M36": "Clock glitch не выполнялся; внешний тактовый тракт на стенде не проверен.",
    "M37": "EMFI-оборудование не использовалось.",
    "M38": "Инъекция на QSPI не выполнялась; есть карта адресов и код проверки.",
    "M39": "Carving намеренно не запускался: ZIP организаторы назвали пасхалкой вне задания.",
    "M40": "Вся SRAM после RESET/BOOTSEL считана, полезные сигнатуры не найдены.",
    "M41": "Ток и ЭМ не измерялись; камера не увидела разницу, наличие задержки подтверждено только кодом.",
    "M42": "Видео или аудиозапись реального ввода владельца не делалась.",
}


def main() -> None:
    report = (ROOT / "CyberSafe_report.md").read_text()
    methods = parse_methods(report)
    summary = json.loads((EVIDENCE / "proof-summary.json").read_text())["catalog"]
    category_by_method = {}
    for key, category in (
        ("A_live_board", "A"),
        ("B_dump_static_or_ready_artifact", "B"),
        ("C_requires_more_equipment_or_build", "C"),
        ("N_negative", "N"),
    ):
        for method_id in summary[key]:
            if method_id in category_by_method:
                raise SystemExit(f"duplicate category: {method_id}")
            category_by_method[method_id] = category

    artifact_index = {}
    rows = []
    for method in methods:
        method_id = method["id"]
        refs = ARTIFACTS[method_id]
        for rel in refs:
            path = ROOT / rel
            if not path.is_file():
                raise SystemExit(f"missing artifact for {method_id}: {rel}")
            artifact_index.setdefault(
                rel,
                {"size_bytes": path.stat().st_size, "sha256": sha256(path)},
            )
        category = category_by_method[method_id]
        proof_kind = {
            "A": "live_board",
            "B": "offline_device_specific",
            "C": "plan_only",
            "N": "negative_result",
        }[category]
        if method_id == "M12":
            proof_kind = "partial_live"
        rows.append(
            {
                **method,
                "root_vector": vector_for(int(method_id[1:])),
                "catalog_category": category,
                "proof_kind": proof_kind,
                "completed_live": category == "A",
                "supporting_artifacts": refs,
                "limitation": LIMITATIONS[method_id],
            }
        )

    if len(rows) != 42 or set(category_by_method) != {f"M{i:02d}" for i in range(1, 43)}:
        raise SystemExit("method categories do not cover M01..M42 exactly")

    result = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "proof and limitation audit for every report method variant",
        "status_legend": {
            "A": "выполнено на живой выданной плате",
            "B": "подтверждено на дампе этой платы или готовым проверенным артефактом",
            "C": "план или частичная проверка; полная атака не выполнена",
            "N": "проверено с отрицательным результатом",
        },
        "counts": {
            "methods": 42,
            "A": sum(row["catalog_category"] == "A" for row in rows),
            "B": sum(row["catalog_category"] == "B" for row in rows),
            "C": sum(row["catalog_category"] == "C" for row in rows),
            "N": sum(row["catalog_category"] == "N" for row in rows),
            "unique_supporting_artifacts": len(artifact_index),
        },
        "methods": rows,
        "artifact_index": dict(sorted(artifact_index.items())),
    }
    (EVIDENCE / "method-proof-matrix.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    )

    lines = [
        "# Пруфы и ограничения для M01–M42",
        "",
        "Эта таблица нужна для финальной проверки отчёта. A означает живой результат, B — результат на дампе или проверенный артефакт, C — план/неполная проверка, N — отрицательный опыт. Разные M внутри одного V не заявляются как разные корневые уязвимости.",
        "",
        "| Метод | Вектор | Статус | Вид пруфа | Файлы | Что не доказано |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        refs = "<br>".join(f"`{ref}`" for ref in row["supporting_artifacts"]) or "—"
        lines.append(
            f"| {row['id']} | {row['root_vector']} | {row['catalog_category']} | "
            f"{row['proof_kind']} | {refs} | {row['limitation']} |"
        )
    lines += [
        "",
        f"Уникальных файлов в этой матрице: {len(artifact_index)}. Их размеры и SHA-256 лежат в `method-proof-matrix.json`.",
    ]
    (EVIDENCE / "METHOD_PROOF_MATRIX.md").write_text("\n".join(lines) + "\n")
    print(
        json.dumps(
            {
                "methods": len(rows),
                "artifacts": len(artifact_index),
                "counts": result["counts"],
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
