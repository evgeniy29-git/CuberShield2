import subprocess

def is_signed(filepath):
    try:
        result = subprocess.run(
            ["sigcheck.exe", "-q", "-n", filepath],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout.strip()
        return "Signed" in output
    except Exception as e:
        return False
