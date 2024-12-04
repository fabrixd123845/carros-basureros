from flask import Blueprint
from routes.api.auth_routes import auth_bp as auth_api_bp
from routes.web.general_routes import web_bp as web_bp

# Crear un Blueprint general para las rutas de la API
api_bp = Blueprint('api', __name__, url_prefix='/api')
api_bp.register_blueprint(auth_api_bp)

# Crear un Blueprint general para las rutas web
# Ya no es necesario registrar 'web_bp' sobre sí mismo.
