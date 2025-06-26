import json

def load_signature_definitions(path="signatures.json"):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Конвертируем строку в байты
            for entry in data:
                entry["signature_bytes"] = bytes(entry["signature"].encode("utf-8").decode("unicode_escape"), "latin1")
            return data
    except Exception as e:
        return []
