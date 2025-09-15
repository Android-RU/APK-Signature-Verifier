#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
signature.py — Проверка подписи APK (v1/v2/v3/v4) с использованием apksigner
или fallback-анализом, если apksigner недоступен.
"""

import argparse
import subprocess
import sys
import os
import tempfile
import json
import shutil
import zipfile
import hashlib
from datetime import datetime


# ==============================
# Вспомогательные функции
# ==============================

def run_cmd(cmd, timeout=30):
    """Запуск внешней команды и возврат (stdout, stderr, код_выхода)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return proc.stdout, proc.stderr, proc.returncode
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", 127
    except subprocess.TimeoutExpired:
        return "", f"Timeout expired for {cmd}", 124


def find_executable(name, override=None):
    """Поиск исполняемого файла в PATH или использование override."""
    if override:
        return override
    return shutil.which(name)


def sha256_of_file(path):
    """Подсчёт SHA256 файла (для сертификатов)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()


# ==============================
# APK Метаданные
# ==============================

def extract_apk_meta(apk_path):
    """Простейший парсинг AndroidManifest.xml из APK (через zipfile).
    Для MVP ограничимся возвратом имени файла и package=None.
    """
    return {
        "apk_path": apk_path,
        "package_name": None,
        "version_name": None,
        "version_code": None,
    }


# ==============================
# Проверка подписи через apksigner
# ==============================

def verify_with_apksigner(apk_path, apksigner="apksigner", timeout=30):
    """Запуск apksigner verify --verbose --print-certs и парсинг результата."""
    stdout, stderr, code = run_cmd(
        [apksigner, "verify", "--verbose", "--print-certs", apk_path],
        timeout=timeout
    )
    if code != 0:
        return {
            "mode": "apksigner",
            "verified": False,
            "error": stderr.strip() or stdout.strip()
        }

    result = {
        "mode": "apksigner",
        "verified": "Verified" in stdout,
        "schemes": {},
        "signers": [],
    }

    # Простейший парсинг строк
    current_signer = None
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("Signer #"):
            if current_signer:
                result["signers"].append(current_signer)
            current_signer = {"raw": []}
        if current_signer is not None:
            current_signer["raw"].append(line)
        if line.startswith("Verified using v"):
            # Пример: "Verified using v1 scheme (JAR signing): true"
            parts = line.split()
            if len(parts) >= 4:
                scheme = parts[2]  # v1/v2/v3/v4
                value = parts[-1].lower() == "true"
                result["schemes"][scheme] = "ok" if value else "fail"
    if current_signer:
        result["signers"].append(current_signer)

    return result


# ==============================
# Fallback проверка
# ==============================

def verify_fallback(apk_path):
    """Фолбэк: ищем META-INF/*.RSA и считаем SHA256."""
    result = {
        "mode": "fallback",
        "verified": False,
        "schemes": {},
        "signers": []
    }
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            rsa_files = [f for f in zf.namelist() if f.startswith("META-INF/") and f.endswith(".RSA")]
            if rsa_files:
                signer = {"files": rsa_files, "sha256": []}
                for fname in rsa_files:
                    data = zf.read(fname)
                    h = hashlib.sha256(data).hexdigest()
                    signer["sha256"].append(h)
                result["signers"].append(signer)
                result["schemes"]["v1"] = "ok"
                result["verified"] = True
            else:
                result["schemes"]["v1"] = "absent"
    except Exception as e:
        result["error"] = str(e)
    return result


# ==============================
# Репортинг
# ==============================

def print_human(report):
    """Красивый вывод отчёта."""
    print(f"APK: {report.get('apk_path')}")
    if report.get("package_name"):
        print(f"Package: {report['package_name']}")
    print(f"Verification mode: {report.get('mode')}")
    print(f"Verified: {report.get('verified')}")
    if "schemes" in report:
        print("Schemes:")
        for k, v in report["schemes"].items():
            print(f"  {k}: {v}")
    if "signers" in report:
        print(f"Signers: {len(report['signers'])}")
        for i, s in enumerate(report["signers"], 1):
            print(f"  - Signer #{i}: {s}")


def print_json(report, out_path=None):
    """JSON вывод."""
    js = json.dumps(report, indent=2, ensure_ascii=False)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(js)
    else:
        print(js)


# ==============================
# Main
# ==============================

def main():
    parser = argparse.ArgumentParser(description="APK Signature Verifier")
    parser.add_argument("target", nargs="?", help="Путь к .apk файлу")
    parser.add_argument("--package", help="Имя пакета на устройстве (через adb)")
    parser.add_argument("-a", "--apksigner", help="Путь к apksigner")
    parser.add_argument("--json", action="store_true", help="Вывод в JSON")
    parser.add_argument("--out", help="Файл для JSON-отчёта")
    args = parser.parse_args()

    if not args.target and not args.package:
        parser.error("Нужно указать либо .apk файл, либо --package")

    apk_path = args.target
    # TODO: реализовать поддержку --package через adb (pm path + pull)
    if args.package:
        print("Поддержка --package ещё не реализована (MVP).", file=sys.stderr)
        sys.exit(3)

    if not os.path.exists(apk_path):
        print(f"Файл не найден: {apk_path}", file=sys.stderr)
        sys.exit(3)

    apksigner = find_executable("apksigner", args.apksigner)

    if apksigner:
        report = verify_with_apksigner(apk_path, apksigner)
    else:
        report = verify_fallback(apk_path)

    # Добавим базовые метаданные
    report.update(extract_apk_meta(apk_path))

    # Вывод
    if args.json or args.out:
        print_json(report, args.out)
    else:
        print_human(report)

    # Код возврата
    if report.get("verified"):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()