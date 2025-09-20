from flask import Flask 
from flask_sqlalchemy import SQLAlchemy
import os
import time

Dir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(Dir, 'enroll.db')


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

semester_dic = {
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
    enrollments = db.relationship('Enrollment', backref= 'user', lazy = True)
class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    course_code = db.Column(db.String(100), nullable= False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable= False)
    
def credits():
    current_credits = 

if __name__ == "__main__":
    app.run(debug=True)