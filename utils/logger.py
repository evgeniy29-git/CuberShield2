import datetime

def log_event(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log = f"[{timestamp}] {message}"
    print(log)
    with open("activity.log", "a", encoding="utf-8") as f:
        f.write(log + "\n")
