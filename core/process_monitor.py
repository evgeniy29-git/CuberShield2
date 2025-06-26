import os
import psutil
import time
from utils.logger import log_event
from utils.signature_checker import is_signed
from utils.hash_tools import get_sha256, check_hash_in_db
import shutil
from datetime import datetime
import pefile

QUARANTINE_DIR = "quarantine"


def analyze_pe_file(pe_path, signatures):
    try:
        pe = pefile.PE(pe_path)
        section_hits = []

        for section in pe.sections:
            data = section.get_data()
            for sig in signatures:
                if sig["signature_bytes"] in data:
                    section_hits.append(
                        f"{sig['name']} (семейство: {sig['family']}) в {section.Name.decode().strip()}"
                    )

        if section_hits:
            return True, "Обнаружены сигнатуры:\n" + "\n".join(section_hits)
        else:
            return False, "Сигнатуры не обнаружены (PE-анализ)."
    except Exception as e:
        return False, f"Ошибка PE-анализа: {e}"




def copy_to_quarantine(src_path, process_name):
    try:
        if not os.path.exists(QUARANTINE_DIR):
            os.makedirs(QUARANTINE_DIR)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{process_name}_{timestamp}.exe"
        dst_path = os.path.join(QUARANTINE_DIR, filename)

        shutil.copy2(src_path, dst_path)
        return dst_path
    except Exception as e:
        log_event(f"[ОШИБКА] Не удалось скопировать файл в карантин: {e}")
        return None

# ...


# ...


# Получаем имя текущего пользователя
USERNAME = os.getlogin()

# Подставляем реальные пути
SUSPICIOUS_DIRS = [
    os.getenv("TEMP"),
    os.getenv("APPDATA"),
    os.getenv("LOCALAPPDATA"),
    f"C:\\ProgramData",
    f"C:\\Users\\Public",
    f"C:\\Users\\{USERNAME}\\Downloads",
    f"C:\\Windows\\Temp",
    f"C:\\Windows\\System32\\config\\systemprofile\\AppData",
    f"C:\\Users\\{USERNAME}\\AppData\\Roaming\\Microsoft\\Windows\\Themes",
    f"C:\\$Recycle.Bin"
]

def is_suspicious_path(path):
    if not path:
        return False
    normalized = os.path.normpath(path).lower()
    return any(normalized.startswith(os.path.normpath(d).lower()) for d in SUSPICIOUS_DIRS if d)

def monitor_processes(poll_interval=2):
    print("[*] Мониторинг процессов с проверкой директорий запуска...")
    seen = set(p.pid for p in psutil.process_iter())

    while True:
        current = set(p.pid for p in psutil.process_iter())
        new = current - seen
        for pid in new:
            try:
                p = psutil.Process(pid)
                exe_path = p.exe()

                if is_suspicious_path(exe_path):
                    signed = is_signed(exe_path)
                    file_hash = get_sha256(exe_path)
                    label = check_hash_in_db(file_hash) if file_hash else "UNKNOWN"

                    log_event(
                        f"[ПОДОЗРИТЕЛЬНО] {p.name()} из {exe_path} "
                        f"(ПОДПИСАН: {signed}, SHA256: {file_hash or 'N/A'}, МЕТКА: {label})"
                    )

                    quarantined_path = copy_to_quarantine(exe_path, p.name())
                    if quarantined_path:
                        log_event(f"[КАРАНТИН] {exe_path} скопирован в {quarantined_path}")
                        is_infected, msg = analyze_pe_file(quarantined_path, virus_signatures)
                        log_event(f"[PE-АНАЛИЗ] {msg}")


                else:
                    log_event(f"Процесс запущен: {p.name()} (PID={pid}), путь: {exe_path}, родитель: {p.ppid()}")


            except Exception as e:
                log_event(f"Не удалось обработать PID {pid}: {e}")

        seen = current
        time.sleep(poll_interval)

