import hashlib

def get_sha256(file_path):
    try:
        with open(file_path, "rb") as f:
            sha256 = hashlib.sha256()
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        return None

def check_hash_in_db(file_hash, db_path="hash_db.txt"):
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("#") or not line.strip():
                    continue
                known_hash, label = line.strip().split()
                if file_hash.lower() == known_hash.lower():
                    return label
        return "UNKNOWN"
    except Exception:
        return "UNKNOWN"
