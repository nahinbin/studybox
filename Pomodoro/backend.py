from flask import redirect, Blueprint, url_for, render_template
from extensions import assignmenet_db
from subject_enrollment.subject import sem_dic, subjects_info
pomodoro_bp = Blueprint('pomodoro', __name__, url_prefix='/pomodoro', template_folder='templates', static_folder='static')


class TimeStudied(assignmenet_db):
    id = assignmenet_db.Column(assignmenet_db.Integer, primary_key = True)
    user_id = assignmenet_db.Column(assignmenet_db.Integer, assignmenet_db.ForeignKey('user.id'))
    subject = assignmenet_db.Column(assignmenet_db.String(50))
    minutes =  assignmenet_db.Column(assignmenet_db.Integer)


@pomodoro_bp.route("/subjects/<int:user_id>")
def pomodoro_home(user_id):
    from app import User
    user = User.query.get_or_404(user_id)
    semester = user.current_semester
    subjects = sem_dic.get(semester)
    sub_name = []
    for subject in subjects:
        name = subjects_info[f'{subject}']['name']
        sub_name.append(name)
    return render_template('subjects.html', subjects = sub_name, user_id = user_id)

#redirect to the pomodoro
@pomodoro_bp.route("/timer/<int:user_id>/<subject>")
def timer_page(user_id, subject):
    return render_template("timer.html", subject=subject, user_id=user_id)

#save
@pomodoro_bp.route("/save/<int:user_id>/<subject>")
def saveTime(user_id, subject):
    return 'nice'