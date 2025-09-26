from flask import redirect, Blueprint, url_for, render_template, request
from extensions import assignmenet_db
from subject_enrollment.subject import sem_dic, subjects_info
pomodoro_bp = Blueprint('pomodoro', __name__, url_prefix='/pomodoro', template_folder='templates', static_folder='static')


class TimeStudied(assignmenet_db.Model):
    id = assignmenet_db.Column(assignmenet_db.Integer, primary_key=True)
    user_id = assignmenet_db.Column(assignmenet_db.Integer, assignmenet_db.ForeignKey('user.id'))
    subject = assignmenet_db.Column(assignmenet_db.String(50))
    minutes = assignmenet_db.Column(assignmenet_db.Integer)


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

    #get the time studied for each subjects
    time_data = {}
    for sub in sub_name:
        record = TimeStudied.query.filter_by(user_id=user_id, subject=sub).first()
        if record:
            time_data[sub] = record.minutes
        else:
            time_data[sub] = 0
    return render_template('subjects.html', subjects = sub_name, user_id = user_id, time=time_data)

#redirect to the pomodoro
@pomodoro_bp.route("/timer/<int:user_id>/<subject>")
def timer_page(user_id, subject):
    return render_template("timer.html", subject=subject, user_id=user_id)

#save
@pomodoro_bp.route("/save/<int:user_id>/<subject>", methods=['POST'])
def saveTime(user_id, subject):
    data = request.get_json()
    minutes = data.get('minutes', 25)
    record = TimeStudied.query.filter_by(user_id=user_id, subject=subject).first()
    if record:
        record.minutes += minutes
    else:
        record = TimeStudied(user_id=user_id, subject=subject, minutes=minutes)
        assignmenet_db.session.add(record)
    assignmenet_db.session.commit()
    
    return {'status': 'success', 'message': f'Studied {minutes} minutes of {subject}'}
    