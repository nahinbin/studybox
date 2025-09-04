from flask import render_template, request, redirect, Blueprint, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os

assignments_bp = Blueprint('assignments', __name__, template_folder='templates', static_folder='static')

#configure the databases(actually start sqlalchemy)

database = SQLAlchemy()

#database 1
class Subject(database.Model):
    id = database.Column(database.Integer, primary_key=True)
    name = database.Column(database.String(100))
    assignments = database.relationship('Assignment', backref='subject', lazy=True, cascade="delete")

#database 2
class Assignment(database.Model):
    id = database.Column(database.Integer, primary_key=True)
    assignment = database.Column(database.String(100))
    deadline = database.Column(database.Date)
    done = database.Column(database.Boolean, default=False)
    linking_dbs = database.Column(database.Integer, database.ForeignKey('subject.id'))


#add assignment/subject
@assignments_bp.route("/", methods=["GET", "POST"])
def tracker_home():
    if request.method == "POST":
        if 'subject_name' in request.form:
            new_subject = request.form.get('subject_name').title()
            subject = Subject(name = new_subject)
            database.session.add(subject)
            database.session.commit()
            return redirect(url_for('assignments.tracker_home'))
        elif 'assignment_name' in request.form and 'deadline' in request.form:
            assignment_name = request.form.get('assignment_name')
            deadline_str = request.form.get('deadline')
            deadline = datetime.strptime(deadline_str, '%Y-%m-%d').date()
            done = request.form.get('done')
            subject_id = request.form.get('subject_id')
            assignment = Assignment(assignment=assignment_name, deadline=deadline, done=bool(done), linking_dbs=subject_id)
            database.session.add(assignment)
            database.session.commit()
            return redirect(url_for('assignments.tracker_home'))
        elif 'assignment_id' in request.form:
            assignment_id = request.form.get('assignment_id')
            done = request.form.get('done')
            done = True if request.form.get('done') == 'True' else False
            assignment = Assignment.query.get(assignment_id)
            assignment.done = bool(done)
            database.session.commit()
            return redirect(url_for('assignments.tracker_home'))
        
    elif request.method == "GET":
        assignments = Assignment.query.all()
        subjects = Subject.query.all()
        return render_template("assignments.html", assignments=assignments, subjects=subjects)
#edit assignment
@assignments_bp.route("/edit/<int:id>", methods=["GET", "POST"])
def edit(id):
    assignment = Assignment.query.get_or_404(id)

    if request.method == "POST":
        assignment.assignment = request.form['assignment']
        assignment.deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d').date()
        database.session.commit()
        return redirect(url_for('assignments.tracker_home'))

    # GET request → show the edit page
    return render_template("edit_assignment.html", assignment=assignment)

#delete assignment
@assignments_bp.route("/delete/<int:id>", methods=["POST"])
def delete(id:int):
    object = Assignment.query.get_or_404(id)
    try:
        database.session.delete(object)
        database.session.commit()
        return redirect(url_for('assignments.tracker_home'))
    except Exception as e:
            return f"ERROR: {e}"

#edit subject
@assignments_bp.route("/edit_subject/<int:subject_id>", methods=["POST"])
def edit_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    subject.name = request.form['subject_name'].title()
    database.session.commit()
    return redirect(url_for('assignments.tracker_home'))

#delete subject
@assignments_bp.route("/delete_subject/<int:subject_id>", methods=["POST"])
def delete_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    database.session.delete(subject)
    database.session.commit()
    return redirect(url_for('assignments.tracker_home'))


