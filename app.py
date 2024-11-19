from flask import Flask, redirect, url_for
from routes import api_bp, web_bp

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta_unica'

# Registrar Blueprints
app.register_blueprint(api_bp)
app.register_blueprint(web_bp)

# Redirigir automáticamente de '/' a '/web/'
@app.route('/')
def home_redirect():
    return redirect(url_for('web_bp.index'))

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
