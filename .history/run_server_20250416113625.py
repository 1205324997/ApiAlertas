import subprocess
import time
import uvicorn
import threading

# Ruta al ejecutable Snort y su configuración
SNORT_COMMAND = [
    "snort", "-i", "4", "-A", "fast", "-c", "C:\\Snort\\etc\\snort.conf", "-l", "C:\\Snort\\log"
]

def run_snort():
    print("[+] Iniciando Snort...")
    subprocess.Popen(SNORT_COMMAND)  # Ya no bloquea el resto del código

def run_api():
    print("[+] Iniciando API FastAPI...")
    uvicorn.run("app:app", reload=True)

if __name__ == "__main__":
    # Ejecutar Snort en un hilo aparte para que se mantenga en segundo plano
    snort_thread = threading.Thread(target=run_snort)
    snort_thread.start()

    # Esperar un poquito para asegurar que Snort comience
    time.sleep(3)

    run_api()
