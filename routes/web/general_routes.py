from flask import Blueprint, render_template, redirect, url_for, request, session, flash
from werkzeug.security import check_password_hash
from models.user_model import User
import jwt
from datetime import datetime, timedelta
from datetime import datetime
import pytz
from db_connection import get_db

web_bp = Blueprint('web_bp', __name__, url_prefix='/web')
SECRET_KEY = "tu_clave_secreta_jwt"

@web_bp.route('/')
def index():
    # Verificar si hay un token en la sesión
    if 'token' not in session:
        # Si no hay token, redirigir a la página de inicio de sesión
        return redirect(url_for('web_bp.auth_login'))
    
    # Si hay token, mostrar el index o la página principal
    return render_template('index.html')

@web_bp.route('/auth/login', methods=['GET', 'POST'])
def auth_login():
    if request.method == 'POST':
        carnet_identidad = request.form.get("username")
        password = request.form.get("password")

        # Buscar usuario por carnet de identidad
        user_data = User.find_by_carnet(carnet_identidad)
        if not user_data:
            flash("Usuario no encontrado", "error")
            return render_template('login.html')

        # Verificar la contraseña
        if not check_password_hash(user_data["password"], password):
            flash("Contraseña incorrecta", "error")
            return render_template('login.html')

        # Validación de rol para acceso en la web
        if user_data["rol"] not in ["superadmin", "admin"]:
            flash("Acceso denegado: solo administradores pueden iniciar sesión en la web", "error")
            return render_template('login.html')

        # Generar el token JWT
        token = jwt.encode({
            "carnet_identidad": user_data["carnet_identidad"],
            "rol": user_data["rol"],
            "exp": datetime.utcnow() + timedelta(hours=2)
        }, SECRET_KEY, algorithm="HS256")

        # Guardar el token en la sesión y redirigir al dashboard
        session['token'] = token
        flash("Inicio de sesión exitoso", "success")
        return redirect(url_for('web_bp.dashboard'))

    return render_template('login.html')

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

        # Obtener conexión a la base de datos
        db = get_db()
        usuarios = db['usuarios']  # Acceder a la colección usuarios

        # Recuperar datos de los usuarios
        lista_personal = []
        for usuario in usuarios.find():
            lista_personal.append({
                "id": str(usuario["_id"]),  # Convertimos ObjectId a string
                "nombre": usuario.get("nombre_completo", "N/A"),
                "carnet": usuario.get("carnet_identidad", "N/A"),
                "vehiculo": usuario.get("carro_asignado", "No asignado"),
                "tipo": usuario.get("cargo", "Desconocido"),
            })

        # Renderizar la página con los datos
        return render_template('lista_personal.html', lista_personal=lista_personal)

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
