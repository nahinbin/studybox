from flask import render_template, redirect, request, url_for, flash, Blueprint 
from extensions import assignmenet_db
 


enrollment_bp = Blueprint("enrollment", __name__, template_folder='templates', static_folder='static')

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
        'assessments': {
            'Assignment': '15%',
            'Quiz': '15%',
            'Project': '20%',
            'Final Exam': '50%'
        }
    },

    'CCT1114': {
        'name': 'Introduction to Computing Technologies',
        'credit_hours': 4,
        'assessments': {
            'Role play': '20%',
            'Project': '30%',
            'Case study': '50%'
        }
    },

    'LCE1113': {
        'name': 'Communicative English',
        'credit_hours': 3,
        'assessments': {
            'Reading Project': '20%',
            'Written Assignment': '20%',
            'Presentation': '30%',
            'Grammar Quiz': '20%'
        }
    },

    'CMT1114': {
        'name': 'Mathematics I',
        'credit_hours': 4,
        'assessments': {
            'Quiz 1': '5%',
            'Quiz 2': '5%',
            'Test 1': '15%',
            'Quiz 3': '5%',
            'Quiz 4': '5%',
            'Test 2': '15%',
            'Final Exam': '50%'
        }
    },

    'CSP1114': {
        'name': 'Problem Solving & Program Design',
        'credit_hours': 4,
        'assessments': {
            'Quiz': '20%',
            'Test': '30%',
            'Assignment': '50%'
        }
    },

    # second sem
    'LCT1113': {
        'name': 'Critical Thinking',
        'credit_hours': 3,
        'assessments': {
            'Presentation': '30%',
            'Debate Project': '40%',
            'Quiz': '30%'
        }
    },

    'CDS1114': {
        'name': 'Introduction to Digital Systems',
        'credit_hours': 4,
        'assessments': {
            'Quiz 1': '5%',
            'Midterm': '20%',
            'Quiz 2': '5%',
            'Assignment': '20%',
            'Final Exam': '50%'
        }
    },

    'LEE1113': {
        'name': 'Essential English',
        'credit_hours': 3,
        'assessments': {
            'Writing Assignment': '30%',
            'Reading Project': '30%',
            'Presentation': '20%',
            'Grammar Quiz': '20%'
        }
    },

    'CMF1114': {
        'name': 'Multimedia Fundamental',
        'credit_hours': 4,
        'assessments': {
            'Lab Assessment 1': '10%',
            'Assignment 1': '25%',
            'Mid-Term': '20%',
            'Lab Assessment 2': '10%',
            'Lab Assessment 3': '10%',
            'Assignment 2': '25%'
        }
    },

    'CMT1124': {
        'name': 'Mathematics II',
        'credit_hours': 4,
        'assessments': {
            'Quiz 1': '5%',
            'Quiz 2': '5%',
            'Test 1': '15%',
            'Quiz 3': '5%',
            'Quiz 4': '5%',
            'Test 2': '15%',
            'Final Exam': '50%'
        }
    },

    'CPP1113': {
        'name': 'Principles of Physics',
        'credit_hours': 3,
        'assessments': {
            'Quiz 1': '10%',
            'Quiz 2': '10%',
            'Midterm Test': '30%',
            'Final Exam': '50%'
        }
    },

    # third se
    'LAE1113': {
        'name': 'Academic English',
        'credit_hours': 3,
        'assessments': {
            'Assignment': '30%',
            'Presentation': '20%',
            'Final Exam': '50%'
        }
    },

    'CMT1134': {
        'name': 'Mathematics III',
        'credit_hours': 4,
        'assessments': {
            'Quiz': '20%',
            'Test': '30%',
            'Final Exam': '50%'
        }
    },

    'CSP1123': {
        'name': 'Mini IT Project',
        'credit_hours': 3,
        'assessments': {
            'Technical Report': '40%',
            'Reporting': '30%',
            'Weekly Progress': '10%',
            'Presentation': '10%',
            'Implementation': '50%'
        }
    }
}


class Enrollment(assignmenet_db.Model):
    id = assignmenet_db.Column(assignmenet_db.Integer, primary_key= True)
    course_code = assignmenet_db.Column(assignmenet_db.String(100), nullable= False)

    user_id = assignmenet_db.Column(assignmenet_db.Integer, assignmenet_db.ForeignKey('user.id'), nullable= False)
    gpa = assignmenet_db.Column(assignmenet_db.Integer, nullable = True, default=0)

    assignments = assignmenet_db.relationship('Assignment', backref='enrollment', lazy=True, cascade="all, delete-orphan")

    def subject_name(self):
        return subjects_info[self.course_code]['name']
    
    def credit_hours(self):
        return subjects_info[self.course_code]['credit_hours']
    
class PreviousSemester(assignmenet_db.Model):
    id = assignmenet_db.Column(assignmenet_db.Integer, primary_key=True)
    name = assignmenet_db.Column(assignmenet_db.String(100), nullable=False)
    user_id = assignmenet_db.Column(assignmenet_db.Integer, assignmenet_db.ForeignKey("user.id"), nullable=False)
    gpa = assignmenet_db.Column(assignmenet_db.Float, nullable=True)  # Store the GPA for this semester
    credits = assignmenet_db.Column(assignmenet_db.Integer, nullable=True)  # Store total credits for this semester

 
def max_credits(user_id, new_subject):
    # Import here to avoid circular imports
    from app import User
    user = User.query.get_or_404(user_id)
    current_credits = 0
    
    # Only count credits from current semester
    current_semester_codes = sem_dic.get(user.current_semester, [])
    for enrollment in user.enrollments:
        if enrollment.course_code in current_semester_codes:
            current_credits += enrollment.credit_hours()
    
    if user.current_semester in ['First Semester', 'Second Semester']:
        max_credit = 21
    else:
        max_credit = 10
    return  current_credits + subjects_info[new_subject]['credit_hours'] <= max_credit

    
@enrollment_bp.route('/semester/<int:user_id>', methods=['GET', 'POST'])
def semesters(user_id):
    from app import User
    user = User.query.get_or_404(user_id)

    # If user is graduated, redirect to dashboard
    if user.graduated:
        flash("You have already graduated! Congratulations!", "success")
        return redirect(url_for("index"))

    # If user already has a current semester, redirect directly to enrollment
    if user.current_semester:
        return redirect(url_for('enrollment.enroll', user_id=user.id))

    if request.method == 'POST':
        user.current_semester = request.form.get('semester')
        assignmenet_db.session.commit()
        return redirect(url_for('enrollment.enroll', user_id=user.id))
    
    elif request.method == 'GET':
        # Get all available semesters
        all_semesters = list(sem_dic.keys())
        
        # Get completed semesters for this user
        completed_semesters = [ps.name for ps in user.previous_semesters]
        
        # Filter out completed semesters
        available_semesters = [sem for sem in all_semesters if sem not in completed_semesters]
        
        return render_template('semester.html', semesters=available_semesters, user=user)
    

@enrollment_bp.route('/enroll/<int:user_id>', methods=['GET', 'POST'])
def enroll(user_id):
    from app import User
    user = User.query.get_or_404(user_id)
    semester = user.current_semester

    # If semester is not set yet, redirect to semester selection
    if not semester:
        return redirect(url_for('enrollment.semesters', user_id=user.id))
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
                # create default tasks from subjects_info assessments (simple)
                from tracker.task_tracker import Assignment  # local import to avoid circular import
                assessments = subjects_info.get(course_code, {}).get('assessments', {})
                for name, pct in assessments.items():
                    # convert pct to a float between 0 and 1
                    weight = float(str(pct).rstrip('%')) / 100
                    assignmenet_db.session.add(Assignment(
                    assignment=name,
                    deadline=None,
                    done=False,
                    enrollment_id=new_enroll.id,
                    weight=weight))
                assignmenet_db.session.commit()
        
        else:
            max_credit = 21 if user.current_semester in ['First Semester', 'Second Semester'] else 10
            flash(f"Cannot enroll in this subject: Max credits of {max_credit} for this semester is exceeded", "error")
        return redirect(url_for('enrollment.enroll', user_id=user.id))

    # Filter enrollments to only show current semester subjects
    current_semester_codes = sem_dic.get(semester, [])
    current_enrollments = [enrollment for enrollment in user.enrollments if enrollment.course_code in current_semester_codes]
    
    return render_template('enroll.html', user=user, current_semester=semester,subjects=subjects, subjects_info=subjects_info,enrollments=current_enrollments)

# only drops the subjects of the current semester
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
    return redirect(url_for('enrollment.semesters', user_id=user.id))

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
        # Check if this semester is already in completed semesters
        existing_prev = PreviousSemester.query.filter_by(user_id=user.id, name=current_semester).first()
        if not existing_prev:
            prev = PreviousSemester(name=current_semester, user=user)
            assignmenet_db.session.add(prev)
        user.current_semester = "Second Semester"

    elif current_semester == "Second Semester":
        # Check if this semester is already in completed semesters
        existing_prev = PreviousSemester.query.filter_by(user_id=user.id, name=current_semester).first()
        if not existing_prev:
            prev = PreviousSemester(name=current_semester, user=user)
            assignmenet_db.session.add(prev)
        user.current_semester = "Third Semester"

    elif current_semester == "Third Semester":
        # Check if this semester is already in completed semesters
        existing_prev = PreviousSemester.query.filter_by(user_id=user.id, name=current_semester).first()
        if not existing_prev:
            prev = PreviousSemester(name=current_semester, user=user)
            assignmenet_db.session.add(prev)
        user.current_semester = None
        user.graduated = True

    assignmenet_db.session.commit()

    # If the user has progressed to a valid next semester, send directly to enroll page
    if user.current_semester:
        flash(f"Moved to {user.current_semester}. Enroll your subjects for this semester.", "success")
        return redirect(url_for("enrollment.enroll", user_id=user.id))

    # If graduated (no current_semester), go back to dashboard
    flash("Congratulations on graduating!", "success")
    return redirect(url_for("index"))


    