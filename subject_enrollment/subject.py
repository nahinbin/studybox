from flask import render_template, redirect, request, url_for, flash, Blueprint 
from extensions import assignmenet_db
# Avoid importing User at module import time to prevent circular imports



enrollment_bp = Blueprint("enrollment", __name__, url_prefix="/enrollment", template_folder='templates', static_folder='static')

sem_dic = {
    'First Semester' : ['GNB1114', 'CCT1114', 'LCE1113', 'CMT1114', 'CSP1114'],
    'Second Semester' : ['LCT1113', 'CDS1114', 'LEE1113', 'CMF1114','CMT1124', 'CPP1113'],
    'Third Semester' : ['LAE1113', 'CMT1134', 'CSP1123',]
}

subjects_info = {
    # first sem
    'GNB1114': {
        'name': 'Introduction to Business Management',
        'credit_hours': 4,
        'assessments': {}
    },

    'CCT1114': {
        'name': 'Introduction to Computing Technologies',
        'credit_hours': 4,
        'assessments': {
            'Project': '30%',
            'Role play': '20%'
        }
    },

    'LCE1113': {
        'name': 'Communicative English',
        'credit_hours': 3,
        'assessments': {}
    },

    'CMT1114': {
        'name': 'Mathematics I',
        'credit_hours': 4,
        'assessments': {
            'Quiz': '20%',
            'Test': '30%'
        }
    },

    'CSP1114': {
        'name': 'Problem Solving & Program Design',
        'credit_hours': 4,
        'assessments': {
            'Quiz': '20%',
            'Test': '30%'
        }
    },

    # second sem
    'LCT1113': {
        'name': 'Critical Thinking',
        'credit_hours': 3,
        'assessments': {}
    },

    'CDS1114': {
        'name': 'Introduction to Digital Systems',
        'credit_hours': 4,
        'assessments': {
            'Quiz': '10%',
            'Test': '20%',
            'Assignment': '20%'
        }
    },

    'LEE1113': {
        'name': 'Essential English',
        'credit_hours': 3,
        'assessments': {}
    },

    'CMF1114': {
        'name': 'Multimedia Fundamental',
        'credit_hours': 4,
        'assessments': {
            'Test': '20%',
            'Lab Assessment': '30%'
        }
    },

    'CMT1124': {
        'name': 'Mathematics II',
        'credit_hours': 4,
        'assessments': {
            'Quiz': '20%',
            'Test': '30%'
        }
    },

    'CPP1113': {
        'name': 'Principles of Physics',
        'credit_hours': 3,
        'assessments': {
            'Test': '30%',
            'Quiz': '20%'
        }
    },

    # third se
    'LAE1113': {
        'name': 'Academic English',
        'credit_hours': 3,
        'assessments': {}
    },

    'CMT1134': {
        'name': 'Mathematics III',
        'credit_hours': 4,
        'assessments': {
            'Quiz': '20%',
            'Test': '30%'
        }
    },

    'CSP1123': {
        'name': 'Mini IT Project',
        'credit_hours': 3,
        'assessments': {
            'Technical Report': '40%'
        }
    }
}


class Enrollment(assignmenet_db.Model):
    id = assignmenet_db.Column(assignmenet_db.Integer, primary_key= True)
    course_code = assignmenet_db.Column(assignmenet_db.String(100), nullable= False)

    user_id = assignmenet_db.Column(assignmenet_db.Integer, assignmenet_db.ForeignKey('user.id'), nullable= False)
    gpa = assignmenet_db.Column(assignmenet_db.Integer, nullable = True)

    assignments = assignmenet_db.relationship('Assignment', backref='enrollment', lazy=True, cascade="all, delete-orphan")

    def subject_name(self):
        return subjects_info[self.course_code]['name']
    
    def credit_hours(self):
        return subjects_info[self.course_code]['credit_hours']
    
class PreviousSemester(assignmenet_db.Model):
    id = assignmenet_db.Column(assignmenet_db.Integer, primary_key=True)
    name = assignmenet_db.Column(assignmenet_db.String(100), nullable=False)
    user_id = assignmenet_db.Column(assignmenet_db.Integer, assignmenet_db.ForeignKey("user.id"), nullable=False)


def max_credits(user_id, new_subject):
    # Import here to avoid circular imports
    from app import User
    user = User.query.get_or_404(user_id)
    current_credits = 0
    for enrollment in user.enrollments:
        current_credits += enrollment.credit_hours()
    if user.current_semester in ['First Semester', 'Second Semester']:
        max_credit = 21
    else:
        max_credit = 10
    return  current_credits + subjects_info[new_subject]['credit_hours'] <= max_credit





# @enrollment_bp.route('/', methods=['GET', 'POST'])
# def user():
#     if request.method == 'POST':
#         new_user = User(username= request.form.get('username'))
#         assignmenet_db.session.add(new_user)
#         assignmenet_db.session.commit()
#         return redirect(url_for('enrollment.user'))
#     if request.method == 'GET':
#         return render_template('users.html', users = User.query.all())
    
@enrollment_bp.route('/semester/<int:user_id>', methods=['GET', 'POST'])
def semesters(user_id):
    from app import User
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.current_semester = request.form.get('semester')
        assignmenet_db.session.commit()
        return redirect(url_for('enrollment.enroll', user_id=user.id))
    
    elif request.method == 'GET':
        semesters = sem_dic.keys()
        return render_template('semester.html', semesters=semesters, user=user)
    

@enrollment_bp.route('/enroll/<int:user_id>', methods=['GET', 'POST'])
def enroll(user_id):
    from app import User
    user = User.query.get_or_404(user_id)
    semester = user.current_semester
    subjects = sem_dic.get(semester)

    if request.method == 'POST':
        course_code = request.form.get('course_code')
        if max_credits(user.id, course_code):
            new_enroll = Enrollment(course_code=course_code, user_id=user.id)
            enrolled_subjects = user.enrollments
            
            # Note: any function gives false only if all the options are false otherwise it gives true
            if any(subject.course_code == course_code for subject in enrolled_subjects):
                flash(f"Subject already enrolled", "warning")
                
            else:
                assignmenet_db.session.add(new_enroll)
                assignmenet_db.session.commit()
        else:
            max_credit = 21 if user.current_semester in ['First Semester', 'Second Semester'] else 10
            flash(f"Cannot enroll in this subject: Max credits of {max_credit} for this semester is exceeded", "error")
        return redirect(url_for('enrollment.enroll', user_id=user.id))

    return render_template('enroll.html', user=user, current_semester=semester,subjects=subjects, subjects_info=subjects_info,enrollments=user.enrollments)

@enrollment_bp.route('/drop_semester/<int:user_id>', methods = ['POST'])
def drop_semester(user_id):
    from app import User
    user = User.query.get_or_404(user_id)
    user_enrollments = user.enrollments
    enrolled_semester = user.current_semester

    for enrollment in user_enrollments:
        if enrollment.course_code in sem_dic[f'{enrolled_semester}']:
            assignmenet_db.session.delete(enrollment)
    assignmenet_db.session.commit()

    user.current_semester = None
    assignmenet_db.session.commit()
    flash(f'{enrolled_semester} has been dropped successfuly'.replace('_', ' '), 'success')
    return redirect(url_for('enrollment.user'))

@enrollment_bp.route('/drop_subject/<int:user_id>/<course_code>', methods = ['POST'])
def drop_subject(user_id, course_code):
    from app import User
    user = User.query.get_or_404(user_id)
    enrollments = user.enrollments
    if any(subject.course_code == course_code for subject in enrollments):
        deletion = Enrollment.query.filter_by(course_code=course_code, user_id=user_id).first_or_404()
        assignmenet_db.session.delete(deletion)
        assignmenet_db.session.commit()
        flash(f"{deletion.subject_name()} Deleted", "success")
    return redirect(url_for('enrollment.enroll', user_id=user_id))

@enrollment_bp.route("/progress/<int:user_id>", methods=["POST"])
def progress(user_id):
    from app import User
    user = User.query.get_or_404(user_id)
    current_semester = user.current_semester

    if current_semester == "First Semester":
        prev = PreviousSemester(name=current_semester, user=user)
        assignmenet_db.session.add(prev)
        user.current_semester = "Second Semester"

    elif current_semester == "Second Semester":
        prev = PreviousSemester(name=current_semester, user=user)
        assignmenet_db.session.add(prev)
        user.current_semester = "Third Semester"

    elif current_semester == "Third Semester":
        prev = PreviousSemester(name=current_semester, user=user)
        assignmenet_db.session.add(prev)
        user.current_semester = None
        user.graduated = True

    assignmenet_db.session.commit()
    return redirect(url_for("enrollment.semesters", user_id=user.id))


    