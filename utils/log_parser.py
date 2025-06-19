# Minimal log parser: returns a list of non-empty lines from a plain text log file.
def parse_log(file_path):
    logs = []
    try:
        # open the log file and read each line
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                # remove leading/trailing whitespace and skip empty lines
                line = line.strip()
                if line:
                    logs.append(line)
    except Exception as e:
        # print an error message if the file cannot be read (e.g., missing or permission error)
        print(f"[log_parser] Error reading {file_path}: {e}")
    # return the list of parsed log lines for further processing
    return logs
