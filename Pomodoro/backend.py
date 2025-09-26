from flask import redirect, Blueprint, url_for, render_template, request, flash
from urllib.parse import unquote #prevents storing decoded info in the database
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
    
    # Get only the subjects from the current semester
    current_codes = sem_dic.get(user.current_semester, [])
    enrolled_subjects = []
    for enrollment in user.enrollments:
        if enrollment.course_code in current_codes:
            enrolled_subjects.append(enrollment.subject_name())

    #get the time studied for each enrolled subject
    time_data = {}
    for sub in enrolled_subjects:
        record = TimeStudied.query.filter_by(user_id=user_id, subject=sub).first()
        if record:
            time_data[sub] = record.minutes
        else:
            time_data[sub] = 0
    return render_template('subjects.html', subjects = enrolled_subjects, user_id = user_id, time=time_data)

#redirect to the pomodoro
@pomodoro_bp.route("/timer/<int:user_id>/<subject>")
def timer_page(user_id, subject):
    return render_template("timer.html", subject=subject, user_id=user_id)

#save
@pomodoro_bp.route("/save/<int:user_id>/<subject>", methods=['POST'])
def saveTime(user_id, subject):
    data = request.get_json()
    minutes = data.get('minutes', 25)
    # Decode the URL-encoded subject name to match what subjects page expects
    subject_decoded = unquote(subject)
    
    record = TimeStudied.query.filter_by(user_id=user_id, subject=subject_decoded).first()
    if record:
        record.minutes += minutes
    else:
        record = TimeStudied(user_id=user_id, subject=subject_decoded, minutes=minutes)
        assignmenet_db.session.add(record)
    assignmenet_db.session.commit()
    
    # Add flash message for successful save
    flash(f'Great job! You studied {minutes} minutes of {subject_decoded}. Keep it up!', 'success')
    
    return {'status': 'success', 'message': f'Studied {minutes} minutes of {subject_decoded}'}
    