# Utility functions to process logs
def parse_log(file_path):
    """
    Parsea un archivo de log (texto plano) y retorna una lista de líneas no vacías.
    Soporta logs en formato .txt (una entrada por línea).
    """
    logs = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    logs.append(line)
    except Exception as e:
        print(f"[log_parser] Error leyendo {file_path}: {e}")
    return logs
