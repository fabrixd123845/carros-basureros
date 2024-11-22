# models/user_model.py
from db_connection import get_db
from werkzeug.security import generate_password_hash
from bson import ObjectId

class User:
    def __init__(self, nombre_completo, carnet_identidad, telefono, cargo, password=None, rol="trabajador", carro_asignado=None):
        self.nombre_completo = nombre_completo
        self.carnet_identidad = int(carnet_identidad)  # Convertir a int
        self.telefono = int(telefono)  # Convertir a int
        self.cargo = cargo
        # Encripta la contraseña solo si no está en formato hash
        self.password = generate_password_hash(password) if password and not password.startswith("pbkdf2:sha256") else password
        self.rol = rol
        self.carro_asignado = ObjectId(carro_asignado) if carro_asignado else None

    @staticmethod
    def find_by_carnet(carnet_identidad):
        db = get_db()
        user_data = db.usuarios.find_one({"carnet_identidad": int(carnet_identidad)})
        return user_data if user_data else None  # Devuelve los datos del usuario en lugar de una instancia de `User`

    def save(self):
        db = get_db()
        user_data = {
            "nombre_completo": self.nombre_completo,
            "carnet_identidad": self.carnet_identidad,
            "telefono": self.telefono,
            "cargo": self.cargo,
            "password": self.password,  # Guarda el hash de la contraseña
            "rol": self.rol,
            "carro_asignado": self.carro_asignado
        }
        db.usuarios.insert_one(user_data)
