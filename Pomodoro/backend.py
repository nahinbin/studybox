from flask import redirect, Blueprint, url_for, render_template
from extensions import assignmenet_db

pomodoro_bp = Blueprint('pomodoro', __name__, url_prefix='/pomodoro', template_folder='templates', static_folder='static')

@pomodoro_bp.route("/")
def pomodoro_home():
    return render_template('study.html')
