from flask import Blueprint, render_template, redirect, url_for, request, session, flash, jsonify,  get_flashed_messages
from werkzeug.security import check_password_hash
from models.user_model import User
import jwt
from datetime import datetime, timedelta
from datetime import datetime
import pytz
from db_connection import get_db
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash
from functools import wraps


web_bp = Blueprint('web_bp', __name__, url_prefix='/web')
SECRET_KEY = "tu_clave_secreta_jwt"

def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'token' not in session:
            return redirect(url_for('web_bp.auth_login'))
        try:
            decoded_token = jwt.decode(session['token'], SECRET_KEY, algorithms=["HS256"])
            if decoded_token["rol"] != "superadmin":
                flash("Acceso denegado. Solo los superadministradores pueden realizar esta acción.", "error")
                return redirect(url_for('web_bp.dashboard'))
        except jwt.ExpiredSignatureError:
            flash("Sesión expirada. Inicie sesión nuevamente.", "error")
            return redirect(url_for('web_bp.auth_login'))
        except jwt.InvalidTokenError:
            flash("Token inválido. Inicie sesión nuevamente.", "error")
            return redirect(url_for('web_bp.auth_login'))
        
        return f(*args, **kwargs)
    return decorated_function


@web_bp.route('/')
def index():
    # Verificar si hay un token en la sesión
    if 'token' not in session:
        # Si no hay token, redirigir a la página de inicio de sesión
        return redirect(url_for('web_bp.auth_login'))
    
    # Si hay token, mostrar el index o la página principal
    return render_template('dashboard.html')

@web_bp.route('/crear_personal', methods=['POST'])
def crear_personal():
    try:
        # Obtener datos del formulario
        data = request.get_json()
        db = get_db()

        # Validar campos obligatorios
        required_fields = ["carnet_identidad", "telefono", "nombre_completo", "cargo"]
        if not all([data.get(field) for field in required_fields]):
            return {"message": "Todos los campos obligatorios deben ser proporcionados"}, 400  # Bad request

        # Verificar si el número de carnet ya existe
        if db['usuarios'].find_one({"carnet_identidad": int(data.get("carnet_identidad"))}):
            return {"message": "El número de carnet ya está registrado"}, 400  # Bad request

        # Validar que el cargo sea uno de los roles permitidos
        if data.get("cargo") not in ["conductor", "operario", "admin", "superadmin"]:
            return {"message": "Cargo no permitido"}, 400  # Bad request

        # Si es conductor, validar que se asigne un carro
        if data.get("cargo") == "conductor" and not data.get("carro_asignado"):
            return {"message": "Un conductor debe ser asignado a un carro"}, 400  # Bad request

        # Preparar el nuevo usuario
        nuevo_usuario = {
            "carnet_identidad": int(data.get("carnet_identidad")),
            "nombre_completo": data.get("nombre_completo"),
            "edad": int(data.get("edad")) if data.get("edad") else None,
            "telefono": int(data["telefono"]),
            "cargo": data.get("cargo"),
            "rol": "trabajador" if data.get("cargo") in ["conductor", "operario"] else data.get("cargo"),
            "carro_asignado": ObjectId(data.get("carro_asignado")) if data.get("cargo") == "conductor" else None
        }

        # Encriptar contraseña solo si el cargo no es "operario"
        if data.get("cargo") != "operario":
            if not data.get("password"):
                return {"message": "La contraseña es obligatoria para este tipo de usuario"}, 400  # Bad request
            nuevo_usuario["password"] = generate_password_hash(data.get("password"))

        # Insertar el usuario en la base de datos
        db['usuarios'].insert_one(nuevo_usuario)

        # Si es conductor, actualizar el carro con el conductor asignado
        if data.get("cargo") == "conductor":
            db['carros'].update_one(
                {"_id": ObjectId(data.get("carro_asignado"))},
                {"$set": {"conductor_asignado": nuevo_usuario["carnet_identidad"]}}
            )

        return {"message": "Personal registrado correctamente"}, 201  # Respuesta exitosa

    except Exception as e:
        print(f"Error al crear personal: {e}")
        return {"message": "Error al registrar el personal"}, 500  # Error del servidor

@web_bp.route('/auth/login', methods=['GET', 'POST'])
def auth_login():
    # Recuperar mensajes flash al cargar la página
    message = ""
    category = ""

    # Obtener los mensajes flash si existen
    flashed_messages = get_flashed_messages(with_categories=True)
    if flashed_messages:
        category, message = flashed_messages[-1]  # Tomar el último mensaje flash

    if request.method == 'POST':
        carnet_identidad = request.form.get("username")
        password = request.form.get("password")

        # Buscar usuario por carnet de identidad
        user_data = User.find_by_carnet(carnet_identidad)
        if not user_data:
            message = "Usuario no registrado"
            category = "error"
        elif user_data["rol"] not in ["superadmin", "admin"]:
            # Validar el rol antes de cualquier otro paso
            message = "Acceso denegado. Este usuario debe iniciar sesión en la aplicación móvil."
            category = "error"
        elif not user_data.get("password"):
            # Si el usuario no tiene contraseña configurada (operarios)
            message = "Acceso denegado. Este usuario debe iniciar sesión en la aplicación móvil."
            category = "error"
        else:
            # Proceder con la validación de contraseña
            if not check_password_hash(user_data["password"], password):
                message = "Contraseña incorrecta"
                category = "error"
            else:
                # Generar el token JWT
                token = jwt.encode({
                    "carnet_identidad": user_data["carnet_identidad"],
                    "rol": user_data["rol"],
                    "exp": datetime.utcnow() + timedelta(hours=2)
                }, SECRET_KEY, algorithm="HS256")

                # Guardar el token en la sesión
                session['token'] = token
                message = "Sesión iniciada correctamente"
                category = "success"
                return redirect(url_for('web_bp.dashboard'))

    return render_template('login.html', message=message, category=category)

@web_bp.route('/dashboard')
def dashboard():
    # Verificación de la existencia del token en la sesión
    if 'token' not in session:
        return redirect(url_for('web_bp.auth_login'))

    try:
        # Decodificación y verificación del token JWT
        decoded_token = jwt.decode(session['token'], SECRET_KEY, algorithms=["HS256"])
        
        # Datos dinámicos para la tabla de trabajadores
        trabajadores = [
            {"nombre": "Juan Andrés López Suárez", "vehiculo": "48A45E", "ruta": "Ruta 1", "hora": "08:30:15"},
            {"nombre": "Ana María Pérez Gómez", "vehiculo": "92B56F", "ruta": "Ruta 2", "hora": "09:00:10"},
        ]

        # Número de reportes por personal (ejemplo, en este caso es 0)
        numero_reportes = 0

        # Total de personal trabajando (ejemplo: 40)
        total_personal = len(trabajadores)

        # Obtener hora y fecha actual (zona horaria de Bolivia)

        bolivia_tz = pytz.timezone('America/La_Paz')
        now = datetime.now(bolivia_tz)
        hora_actual = now.strftime("%H:%M:%S")
        fecha_actual = now.strftime("%d/%m/%Y")

        # Renderizar plantilla con datos dinámicos
        return render_template(
            'dashboard.html',
            user=decoded_token,
            trabajadores=trabajadores,
            numero_reportes=numero_reportes,
            total_personal=total_personal,
            hora_actual=hora_actual,
            fecha_actual=fecha_actual,
        )
    except jwt.ExpiredSignatureError:
        flash("Sesión expirada. Por favor, inicie sesión de nuevo.", "error")
        return redirect(url_for('web_bp.auth_login'))
    except jwt.InvalidTokenError:
        flash("Token inválido. Inicie sesión de nuevo.", "error")
        return redirect(url_for('web_bp.auth_login'))
    
@web_bp.route('/lista_personal')
def lista_personal():
    if 'token' not in session:
        return redirect(url_for('web_bp.auth_login'))

    try:
        decoded_token = jwt.decode(session['token'], SECRET_KEY, algorithms=["HS256"])
        user_role = decoded_token["rol"]  # Obtener el rol del usuario autenticado

        # Obtener conexión a la base de datos
        db = get_db()
        usuarios = db['usuarios']  # Acceder a la colección usuarios

        # Recuperar datos de los usuarios
        lista_personal = []
        for usuario in usuarios.find():
            # Filtrar usuarios según el rol
            if user_role != "superadmin" and usuario.get("cargo") not in ["conductor", "operario"]:
                continue

            lista_personal.append({
                "id": str(usuario["_id"]),  # Convertimos ObjectId a string
                "nombre": usuario.get("nombre_completo", "N/A"),
                "carnet": usuario.get("carnet_identidad", "N/A"),
                "edad": usuario.get("edad", "N/A"),
                "telefono": usuario.get("telefono", "N/A"),
                "vehiculo": usuario.get("carro_asignado", "No asignado"),
                "tipo": usuario.get("cargo", "Desconocido"),
            })

        # Renderizar la página con los datos
        return render_template('lista_personal.html', lista_personal=lista_personal, user_role=user_role)

    except jwt.ExpiredSignatureError:
        flash("Sesión expirada. Por favor, inicie sesión de nuevo.", "error")
        return redirect(url_for('web_bp.auth_login'))
    except jwt.InvalidTokenError:
        flash("Token inválido. Inicie sesión de nuevo.", "error")
        return redirect(url_for('web_bp.auth_login'))


@web_bp.route('/logout', methods=['GET'])
def logout():
    # Eliminar el token de sesión
    session.pop('token', None)
    flash("Sesión cerrada exitosamente", "success")
    # Redirigir al login
    return redirect(url_for('web_bp.auth_login'))


@web_bp.route('/nuevo_personal')
def nuevo_personal():
    # Obtener el rol del usuario actual desde el token o la sesión
    decoded_token = jwt.decode(session.get('token'), SECRET_KEY, algorithms=["HS256"])
    user_role = decoded_token["rol"]

    # Obtener los carros disponibles para asignar a los conductores
    db = get_db()
    carros_libres = list(db['carros'].find({"conductor_asignado": None}))  # Buscar carros sin conductor asignado

    # Pasar los carros y el rol del usuario al template
    return render_template('nuevo_personal.html', carros_disponibles=carros_libres, user_role=user_role)

@web_bp.route('/eliminar_personal/<string:user_id>', methods=['DELETE'])
def eliminar_personal(user_id):
    try:
        db = get_db()
        result = db['usuarios'].delete_one({"_id": ObjectId(user_id)})
        if result.deleted_count > 0:
            return jsonify({"message": "Usuario eliminado correctamente"}), 200
        else:
            return jsonify({"message": "Usuario no encontrado"}), 404
    except Exception as e:
        print(f"Error al eliminar usuario: {e}")
        return jsonify({"message": "Error interno del servidor"}), 500

@web_bp.route('/editar_personal/<string:user_id>', methods=['GET', 'PUT'])
def editar_personal(user_id):
    db = get_db()

    if request.method == 'GET':
        # Obtener el rol del usuario autenticado desde el token
        decoded_token = jwt.decode(session.get('token'), SECRET_KEY, algorithms=["HS256"])
        user_role = decoded_token["rol"]

        # Obtener datos del usuario a editar
        user = db['usuarios'].find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"message": "Usuario no encontrado"}), 404

        # Obtener los carros disponibles para asignar si es conductor
        carros_libres = list(db['carros'].find({"conductor_asignado": None}))

        return render_template(
            'editar_personal.html',
            user=user,
            carros_disponibles=carros_libres,
            user_role=user_role
        )

    if request.method == 'PUT':
        try:
            # Obtener datos enviados desde el formulario
            data = request.get_json()

            # Validar campos obligatorios
            required_fields = ["nombre_completo", "telefono", "edad", "cargo"]
            if not all([data.get(field) for field in required_fields]):
                return jsonify({"message": "Todos los campos obligatorios deben ser proporcionados"}), 400

            # Validar que el cargo sea válido
            if data["cargo"] not in ["conductor", "operario", "admin", "superadmin"]:
                return jsonify({"message": "Cargo no permitido"}), 400

            # Restricciones según el rol del usuario autenticado
            decoded_token = jwt.decode(session.get('token'), SECRET_KEY, algorithms=["HS256"])
            user_role = decoded_token["rol"]

            if user_role == "admin" and data["cargo"] not in ["conductor", "operario"]:
                return jsonify({"message": "No tiene permisos para asignar este rol"}), 403

            # Si es conductor, validar que se asigne un carro
            if data["cargo"] == "conductor" and not data.get("carro_asignado"):
                return jsonify({"message": "Un conductor debe ser asignado a un carro"}), 400

            updates = {
                "nombre_completo": data["nombre_completo"],
                "telefono": int(data["telefono"]),
                "edad": int(data["edad"]),
                "cargo": data["cargo"]
            }

            # Eliminar contraseña si es operario, encriptar si no lo es
            if data["cargo"] == "operario":
                db['usuarios'].update_one({"_id": ObjectId(user_id)}, {"$unset": {"password": ""}})
            elif data.get("password"):
                updates["password"] = generate_password_hash(data["password"])

            # Si el cargo es conductor, asignar un carro
            if data["cargo"] == "conductor" and data.get("carro_asignado"):
                updates["carro_asignado"] = ObjectId(data["carro_asignado"])

            # Actualizar el usuario en la base de datos
            result = db['usuarios'].update_one({"_id": ObjectId(user_id)}, {"$set": updates})

            if result.matched_count > 0:
                return jsonify({"message": "Usuario actualizado correctamente"}), 200
            else:
                return jsonify({"message": "Usuario no encontrado"}), 404

        except Exception as e:
            print(f"Error al editar personal: {e}")
            return jsonify({"message": "Error al actualizar el personal"}), 500


@web_bp.route('/lista_vehiculos')
def lista_vehiculos():
    if 'token' not in session:
        return redirect(url_for('web_bp.auth_login'))

    try:
        decoded_token = jwt.decode(session['token'], SECRET_KEY, algorithms=["HS256"])
        user_role = decoded_token["rol"]

        # Obtener conexión a la base de datos
        db = get_db()
        carros = db['carros']  # Acceder a la colección carros

        # Recuperar datos de los carros
        lista_vehiculos = []
        for carro in carros.find():
            # Buscar conductor y ayudantes en la colección de usuarios
            conductor = db['usuarios'].find_one({"_id": carro.get("conductor")})
            ayudantes = [db['usuarios'].find_one({"_id": ayudante}) for ayudante in carro.get("ayudantes", [])]

            lista_vehiculos.append({
                "id": str(carro["_id"]),
                "codigo_interno": carro.get("codigo_interno", "N/A"),
                "placa": carro.get("placa", "N/A"),
                "marca": carro.get("marca", "N/A"),
                "conductor": conductor["nombre_completo"] if conductor else "Sin conductor asignado",
                "ayudantes": ", ".join([ayudante["nombre_completo"] for ayudante in ayudantes if ayudante]),
            })

        # Renderizar la página con los datos
        return render_template('lista_vehiculos.html', lista_vehiculos=lista_vehiculos, user_role=user_role)

    except jwt.ExpiredSignatureError:
        flash("Sesión expirada. Por favor, inicie sesión de nuevo.", "error")
        return redirect(url_for('web_bp.auth_login'))
    except jwt.InvalidTokenError:
        flash("Token inválido. Inicie sesión de nuevo.", "error")
        return redirect(url_for('web_bp.auth_login'))
