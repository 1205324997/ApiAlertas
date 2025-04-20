from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List
from pydantic import BaseModel
import os
import subprocess
import time
import uvicorn
import threading
import json

app = FastAPI()

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modelo de alerta
class Alert(BaseModel):
    timestamp: str
    ip_src: str
    ip_dst: str
    protocol: str
    alert: str
    description: str

# Modelo de persona
class Person(BaseModel):
    name: str
    email: str
    password: str

# Base de datos en memoria
people_db = []

# Archivo JSON donde se guardan los usuarios
DATA_FILE = "people_db.json"

def load_people():
    global people_db
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            data = json.load(file)
            people_db = [Person(**item) for item in data]

def save_people():
    with open(DATA_FILE, "w") as file:
        json.dump([person.dict() for person in people_db], file, indent=4)

# Cargar personas al iniciar
load_people()

@app.get("/api/alerts", response_model=List[Alert])
async def get_alerts():
    alert_path = r'C:\Snort\log\alert.ids'
    if not os.path.exists(alert_path):
        raise HTTPException(status_code=404, detail="Archivo de alertas no encontrado")

    try:
        with open(alert_path, 'r', encoding='utf-8', errors='ignore') as file:
            lines = file.readlines()

        # Palabras clave que consideramos "alertas importantes"
        keywords = [
            "trojan", "malware", "exploit", "sql injection", "dos", 
            "denial of service", "worm", "backdoor", "shellcode", "botnet"
        ]

        alerts = []
        for line in reversed(lines):
            if "[**]" not in line or "[Classification:" not in line:
                continue

            try:
                parts = line.strip().split()
                description = line.split("[**]")[1].split("[Classification:")[0].strip()

                # Solo guardar si contiene alguna palabra clave
                if any(keyword in description.lower() for keyword in keywords):
                    alert_data = {
                        "timestamp": parts[0],
                        "ip_src": parts[-4],
                        "ip_dst": parts[-3],
                        "protocol": parts[-2],
                        "alert": parts[1],
                        "description": description
                    }
                    alerts.append(alert_data)

                # Limitar a las 50 alertas más importantes
                if len(alerts) >= 50:
                    break

            except Exception as e:
                print(f"Error al procesar línea: {line}\n{e}")
                continue

        if not alerts:
            raise HTTPException(status_code=404, detail="No se encontraron alertas importantes.")
        
        return alerts

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al leer alertas: {str(e)}")


@app.post("/api/persons")
async def register_person(person: Person):
    for existing_person in people_db:
        if existing_person.email == person.email:
            raise HTTPException(status_code=400, detail="La persona con este email ya está registrada.")
    people_db.append(person)
    save_people()
    return {"message": "Persona registrada exitosamente", "person": person}

@app.get("/api/persons", response_model=List[Person])
async def get_all_persons():
    if not people_db:
        raise HTTPException(status_code=404, detail="No hay personas registradas.")
    return people_db

@app.get("/api/persons/{email}", response_model=Person)
async def get_person(email: str):
    for person in people_db:
        if person.email == email:
            return person
    raise HTTPException(status_code=404, detail="Persona no encontrada")

@app.delete("/api/persons/{email}")
async def delete_person(email: str):
    global people_db
    people_db = [person for person in people_db if person.email != email]
    save_people()
    return {"message": "Persona eliminada exitosamente"}

# Configuración de Snort
SNORT_COMMAND = [
    "snort", "-i", "4", "-A", "fast", "-c", "C:\\Snort\\etc\\snort.conf", "-l", "C:\\Snort\\log"
]

def run_snort():
    print("[+] Iniciando Snort...")
    subprocess.Popen(SNORT_COMMAND)

def run_api():
    print("[+] Iniciando API FastAPI...")
    uvicorn.run("app:app", reload=True)

if __name__ == "__main__":
    snort_thread = threading.Thread(target=run_snort)
    snort_thread.start()
    time.sleep(3)
    run_api()
