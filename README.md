# Проверка подписи APK

**signature.py** — это инструмент командной строки для проверки подписи APK-файлов. Скрипт позволяет анализировать подпись Android-приложений, определять используемые схемы (v1/v2/v3/v4), извлекать информацию о сертификатах и сравнивать их с эталонными отпечатками. Подходит как для локальных APK, так и для установленных приложений на устройстве (через `adb`).

---

## ✨ Возможности

- Проверка подписи APK с помощью `apksigner` (Android SDK build-tools).  
- Фолбэк-анализ (если `apksigner` недоступен).  
- Определение используемых схем подписи (v1/v2/v3/v4).  
- Извлечение информации о подписантах и сертификатах.  
- Вывод отчёта в человекочитаемом виде или JSON.  
- Поддержка базового анализа APK без распаковки.  
- Коды возврата для интеграции в CI/CD.  

---

## 🔧 Требования

- Python 3.9+  
- ОС: Linux / macOS / Windows  
- Опционально:  
  - `apksigner` (Android SDK build-tools) для полноценной проверки  
  - `adb` для проверки APK прямо с устройства  

---

## 🚀 Установка

```bash
git clone https://github.com/Android-RU/APK-Signature-Verifier.git
cd APK-Signature-Verifier
````

Скрипт не требует установки как пакета. Можно запускать напрямую:

```bash
python3 signature.py <путь_к_APK>
```

---

## 🖥️ Использование

### Базовая проверка локального APK

```bash
python3 signature.py app-release.apk
```

### Вывод в JSON

```bash
python3 signature.py app-release.apk --json
```

### Сохранение JSON-отчёта в файл

```bash
python3 signature.py app-release.apk --json --out report.json
```

### Проверка установленного приложения (через adb)

```bash
python3 signature.py --package com.example.app
```

---

## 📊 Пример вывода

**Человекочитаемый отчёт:**

```
APK: app-release.apk
Verification mode: apksigner
Verified: True
Schemes:
  v1: ok
  v2: ok
  v3: ok
Signers: 1
  - Signer #1: {...}
```

**JSON-отчёт:**

```json
{
  "apk_path": "app-release.apk",
  "verification_mode": "apksigner",
  "verified": true,
  "schemes": {
    "v1": "ok",
    "v2": "ok",
    "v3": "ok"
  },
  "signers": [
    {
      "sha256": "3f1a...9c"
    }
  ]
}
```

---

## 📦 Интеграция в CI/CD

Скрипт возвращает коды выхода:

* `0` — подпись валидна
* `1` — подпись невалидна
* `3` — ошибка ввода/CLI
* `127/124` — проблемы с окружением или таймаут

Пример использования в GitHub Actions:

```yaml
- name: Verify APK Signature
  run: python3 signature.py app-release.apk
```

---

## 📜 Лицензия

Проект распространяется под лицензией **MIT**.
Подробнее см. [LICENSE](LICENSE).
