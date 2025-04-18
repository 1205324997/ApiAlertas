from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List
from pydantic import BaseModel
import os
import subprocess
import time
import uvicorn
import threading
import logging

app = FastAPI()

# Configurar CORS para permitir solicitudes desde cualquier origen
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # O puedes restringir, por ejemplo: ["http://localhost:4200"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modelo de datos para una alerta
class Alert(BaseModel):
    timestamp: str
    ip_src: str
    ip_dst: str
    protocol: str
    alert: str
    description: str

# Modelo de datos para una persona (sin edad y con contraseña en texto plano)
class Person(BaseModel):
    name: str
    email: str
    password: str  # Contraseña en texto plano (no se encripta)

# Lista en memoria para almacenar las personas registradas
people_db = []

@app.get("/api/alerts", response_model=List[Alert])
async def get_alerts():
    alert_path = r'C:\Snort\log\alert.ids'
    if not os.path.exists(alert_path):
        raise HTTPException(status_code=404, detail="Archivo de alertas no encontrado")
    
    try:
        with open(alert_path, 'r', encoding='utf-8', errors='ignore') as file:
            lines = file.readlines()

        # Leer las últimas 100 líneas en lugar de las primeras
        lines = lines[-100:]

        alerts = []
        for line in lines:
            try:
                alert_data = {
                    "timestamp": line.split(" ")[0],
                    "ip_src": line.split(" ")[-4],
                    "ip_dst": line.split(" ")[-3],
                    "protocol": line.split(" ")[-2],
                    "alert": line.split(" ")[1],
                    "description": line.split("[**]")[1].split("[Classification:")[0].strip()
                }
                alerts.append(alert_data)
            except Exception as parse_error:
                print(f"Error al parsear la línea: {line}\nDetalle: {parse_error}")
        return alerts
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Ruta para registrar personas
@app.post("/api/persons")
async def register_person(person: Person):
    # Verificar si la persona ya está registrada (basado en el email)
    for existing_person in people_db:
        if existing_person.email == person.email:
            raise HTTPException(status_code=400, detail="La persona con este email ya está registrada.")
    
    # Registrar la persona sin modificar la contraseña
    people_db.append(person)
    return {"message": "Persona registrada exitosamente", "person": person}

# Ruta para obtener todas las personas registradas (sin incluir contraseñas)
@app.get("/api/persons", response_model=List[Person])
async def get_all_persons():
    if not people_db:
        raise HTTPException(status_code=404, detail="No hay personas registradas.")
    return people_db

# Ruta para obtener una persona por email (sin incluir la contraseña)
@app.get("/api/persons/{email}", response_model=Person)
async def get_person(email: str):
    for person in people_db:
        if person.email == email:
            return person  # Devolver el objeto Person completo
    raise HTTPException(status_code=404, detail="Persona no encontrada")

# Ruta para eliminar una persona por email
@app.delete("/api/persons/{email}")
async def delete_person(email: str):
    global people_db
    people_db = [person for person in people_db if person.email != email]
    return {"message": "Persona eliminada exitosamente"}

# Comando de Snort y configuración
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
