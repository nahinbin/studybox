from flask import render_template, request, redirect, Blueprint, url_for
from extensions import assignmenet_db
from datetime import datetime
from sqlalchemy import ForeignKey
from subject_enrollment.subject import Enrollment, subjects_info

assignments_bp = Blueprint('assignments', __name__, template_folder='templates', static_folder='static')


# assignmenet_db is provided by extensions


# class Subject(assignmenet_db.Model):
#     id = assignmenet_db.Column(assignmenet_db.Integer, primary_key=True)
#     name = assignmenet_db.Column(assignmenet_db.String(100))
#     assignments = assignmenet_db.relationship('Assignment', backref='subject', lazy=True, cascade="delete")


class Assignment(assignmenet_db.Model):
    id = assignmenet_db.Column(assignmenet_db.Integer, primary_key=True)
    assignment = assignmenet_db.Column(assignmenet_db.String(100))
    deadline = assignmenet_db.Column(assignmenet_db.Date)
    done = assignmenet_db.Column(assignmenet_db.Boolean, default=False)
    enrollment_id = assignmenet_db.Column(assignmenet_db.Integer, ForeignKey('enrollment.id'))
    score = assignmenet_db.Column(assignmenet_db.Float, nullable=True)  # actual score achieved
    max_score = assignmenet_db.Column(assignmenet_db.Float, nullable=True)  # maximum possible score
    weight = assignmenet_db.Column(assignmenet_db.Float, nullable=True)


#add assignment/subject
@assignments_bp.route("/", methods=["GET", "POST"])
def tracker_home():
    if request.method == "POST":
        # if 'subject_name' in request.form:
        #     new_subject = request.form.get('subject_name').title()
        #     subject = Enrollment(name = new_subject)
        #     assignmenet_db.session.add(subject)
        #     assignmenet_db.session.commit()
        #     return redirect(url_for('assignments.tracker_home'))

        # args contains all query  parameters from the url as a dictionary-like object
        # get retrieves a value from the dictionary so here it retrieves user_id from the url
        user_id = request.args.get('user_id')
        
        # update a task max score
        if 'update_score' in request.form and 'assignment_id' in request.form:
            assignment_id = int(request.form.get('assignment_id'))
            max_score_val = request.form.get('max_score')
            assignment = Assignment.query.get(assignment_id)
            assignment.max_score = float(max_score_val) if max_score_val not in (None, "") else None
            assignmenet_db.session.commit()
            return redirect(url_for('assignments.tracker_home', user_id=user_id))

        # update deadline
        elif 'update_deadline' in request.form and 'assignment_id' in request.form:
            assignment_id = int(request.form.get('assignment_id'))
            deadline_str = request.form.get('deadline')
            assignment = Assignment.query.get(assignment_id)
            if deadline_str:
                assignment.deadline = datetime.strptime(deadline_str, '%Y-%m-%d').date()
            else:
                assignment.deadline = None
            assignmenet_db.session.commit()
            return redirect(url_for('assignments.tracker_home', user_id=user_id))

        # marking assignment as done/not done
        elif 'assignment_id' in request.form:
            assignment_id = request.form.get('assignment_id')
            done = request.form.get('done')
            done = True if request.form.get('done') == 'True' else False
            assignment = Assignment.query.get(assignment_id)
            assignment.done = bool(done)
            assignmenet_db.session.commit()
            return redirect(url_for('assignments.tracker_home', user_id=user_id))
        
    elif request.method == "GET":
        # Get user_id from URL parameter
        user_id = request.args.get('user_id')
        if user_id:
            from app import User
            from subject_enrollment.subject import sem_dic
            user = User.query.get_or_404(user_id)
            
            # Only show subjects from current semester
            current_semester = user.current_semester
            current_semester_codes = sem_dic.get(current_semester, [])
            
            # Filter subjects by user and current semester
            subjects = Enrollment.query.filter_by(user_id=user_id).filter(Enrollment.course_code.in_(current_semester_codes)).all()
            # Get all assignments for the user's current semester subjects
            subject_ids = [subject.id for subject in subjects]
            assignments = Assignment.query.filter(Assignment.enrollment_id.in_(subject_ids)).all()
        else:
            # Fallback to all subjects if no user_id provided
            subjects = Enrollment.query.all()
            assignments = Assignment.query.all()
        return render_template("assignments.html", assignments=assignments, subjects=subjects, now= datetime.now().date())
    
#edit assignment
@assignments_bp.route("/edit/<int:id>", methods=["GET", "POST"])
def edit(id):
    assignment = Assignment.query.get_or_404(id)

    if request.method == "POST":
        assignment.assignment = request.form['assignment']
        assignment.deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d').date()
        assignmenet_db.session.commit()
        return redirect(url_for('assignments.tracker_home'))

    return render_template("edit_assignment.html", assignment=assignment)

#delete assignment
@assignments_bp.route("/delete/<int:id>", methods=["POST"])
def delete(id:int):
    object = Assignment.query.get_or_404(id)
    try:
        assignmenet_db.session.delete(object)
        assignmenet_db.session.commit()
        return redirect(url_for('assignments.tracker_home'))
    except Exception as e:
            return f"ERROR: {e}"

# edit subject
# @assignments_bp.route("/edit_subject/<int:subject_id>", methods=["POST"])
# def edit_subject(subject_id):
#     subject = Enrollment.query.get_or_404(subject_id)
#     subject.name = request.form['subject_name'].title()
#     assignmenet_db.session.commit()
#     return redirect(url_for('assignments.tracker_home'))

# delete subject
# @assignments_bp.route("/delete_subject/<int:subject_id>", methods=["POST"])
# def delete_subject(subject_id):
#     subject = Enrollment.query.get_or_404(subject_id)
#     assignmenet_db.session.delete(subject)
#     assignmenet_db.session.commit()
#     return redirect(url_for('assignments.tracker_home'))

