# Minimal log parser: returns a list of non-empty lines from a plain text log file.
def parse_log(file_path):
    logs = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    logs.append(line)
    except Exception as e:
        print(f"[log_parser] Error reading {file_path}: {e}")
    return logs
