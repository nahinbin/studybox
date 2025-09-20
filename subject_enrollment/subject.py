from flask import Flask, render_template, redirect, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy
import os

Dir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(Dir, 'enroll.db')


app = Flask(__name__)
app.config['SECRET_KEY'] = '9807432987490123874132098'

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

sem_dic = {
    'sem_one' : ['GNB1114', 'CCT1114', 'LCE1113', 'CMT1114', 'CSP1114'],
    'sem_two' : ['LCT1113', 'CDS1114', 'LEE1113', 'CMF1114','CMT1124', 'CPP1113'],
    'sem_three' : ['LAE1113', 'CMT1134', 'CSP1123',]
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


class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(100), nullable = False, unique = True)
    semester = db.Column(db.String(100), nullable= True)
    enrollments = db.relationship('Enrollment', backref= 'user', lazy = True)

class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    course_code = db.Column(db.String(100), nullable= False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable= False)


def max_credits(user_id, new_subject):
    user = User.query.get_or_404(user_id)
    subjects = []
    for enrollment in user.enrollments:
        subjects.append(enrollment.course_code)
    current_credits = 0
    for course_code in subjects:
        credits = subjects_info[course_code]['credit_hours']
        current_credits += credits
    if user.semester in ['sem_one', 'sem_two']:
        max_credit = 20
    else:
        max_credit = 10
    return  current_credits + subjects_info[new_subject]['credit_hours'] <= max_credit

@app.route('/', methods=['GET', 'POST'])
def user():
    if request.method == 'POST':
        new_user = User(username= request.form.get('username'))
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('user'))
    if request.method == 'GET':
        return render_template('users.html', users = User.query.all())
    
@app.route('/semester/<int:user_id>', methods=['GET', 'POST'])
def semesters(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.semester = request.form.get('semester')
        db.session.commit()
        return redirect(url_for('enroll', user_id=user.id))
    
    elif request.method == 'GET':
        semesters = sem_dic.keys()
        return render_template('semester.html', semesters=semesters, user=user)
    

@app.route('/enroll/<int:user_id>', methods=['GET', 'POST'])
def enroll(user_id):
    user = User.query.get_or_404(user_id)
    semester = user.semester
    subjects = sem_dic.get(semester)

    if request.method == 'POST':
        course_code = request.form.get('course_code')
        if max_credits(user.id, course_code):
            new_enroll = Enrollment(course_code=course_code, user_id=user.id)
            db.session.add(new_enroll)
            db.session.commit()
        
        else:
            max_credit = 20 if user.semester in ['sem_one', 'sem_two'] else 10
            flash(f"Cannot enroll in this subject:Max credits of {max_credit} is exceeded", "error")
        return redirect(url_for('enroll', user_id=user.id))

    return render_template('enroll.html', user=user, semester=semester,subjects=subjects, subjects_info=subjects_info,enrollments=user.enrollments)

    

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)