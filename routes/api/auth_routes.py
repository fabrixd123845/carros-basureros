# routes/auth_routes.py
from flask import Blueprint, request, jsonify
from models.user_model import User
from werkzeug.security import check_password_hash
import jwt
from datetime import datetime, timedelta

auth_bp = Blueprint('auth', __name__)
SECRET_KEY = "tu_clave_secreta_jwt"

@auth_bp.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    carnet_identidad = data.get('carnet_identidad')
    password = data.get('password')
    platform = data.get('platform')  # Añadimos el origen de la plataforma

    # Buscar usuario por carnet de identidad
    user_data = User.find_by_carnet(carnet_identidad)
    if not user_data:
        return jsonify({"error": "Usuario no encontrado"}), 404

    # Verificar la contraseña usando los datos recuperados directamente
    if not check_password_hash(user_data["password"], password):
        return jsonify({"error": "Contraseña incorrecta"}), 401

    # Validación de plataforma según el rol
    if user_data["rol"] == "trabajador" and platform == "web":
        return jsonify({"error": "Acceso denegado: los conductores solo pueden iniciar sesión en la app móvil"}), 403
    elif user_data["rol"] in ["superadmin", "admin"] and platform == "mobile":
        return jsonify({"error": "Acceso denegado: los administradores solo pueden iniciar sesión en la web"}), 403

    # Generar el token JWT
    token = jwt.encode({
        "carnet_identidad": user_data["carnet_identidad"],
        "rol": user_data["rol"],
        "exp": datetime.utcnow() + timedelta(hours=2)
    }, SECRET_KEY, algorithm="HS256")

    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": {
            "nombre_completo": user_data["nombre_completo"],
            "carnet_identidad": user_data["carnet_identidad"],
            "telefono": user_data["telefono"],
            "cargo": user_data["cargo"],
            "rol": user_data["rol"]
        }
    }), 200

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    nombre_completo = data.get('nombre_completo')
    carnet_identidad = data.get('carnet_identidad')
    telefono = data.get('telefono')
    cargo = data.get('cargo')
    password = data.get('password')
    rol = data.get('rol', 'trabajador')
    carro_asignado = data.get('carro_asignado')

    # Validación de datos
    if not nombre_completo or not carnet_identidad or not telefono or not cargo or not password:
        return jsonify({"error": "Faltan datos obligatorios"}), 400

    # Verificar si el usuario ya existe
    existing_user = User.find_by_carnet(carnet_identidad)
    if existing_user:
        return jsonify({"error": "El usuario con este carnet ya existe"}), 400

    # Crear un nuevo usuario
    new_user = User(
        nombre_completo=nombre_completo,
        carnet_identidad=carnet_identidad,
        telefono=telefono,
        cargo=cargo,
        password=password,
        rol=rol,
        carro_asignado=carro_asignado
    )
    new_user.save()

    return jsonify({"message": "Usuario registrado exitosamente"}), 201
