from flask import Flask, render_template, redirect, request, url_for, Blueprint
import os
from extensions import assignmenet_db
from subject_enrollment.subject import Enrollment
# Avoid importing User at module scope to prevent circular import

DIR = os.path.abspath(os.path.dirname(__file__))
templates_dir = os.path.join(DIR, "templates")
static_dir = os.path.join(DIR, "static")


gpa_bp = Blueprint("gpa", __name__, template_folder=f"{templates_dir}", static_folder=f"{static_dir}")

# class Enrollment(assignmenet_db.Model):
#     id = assignmenet_db.Column(assignmenet_db.Integer, primary_key = True)
#     name = assignmenet_db.Column(assignmenet_db.String(50), nullable = False)
#     gpa = assignmenet_db.Column(assignmenet_db.Float, default = 0)
#     credits = assignmenet_db.Column(assignmenet_db.Integer)

def calc_gpa(user):
    subjects = Enrollment.query.filter_by(user_id=user.id, semester=user.current_semester).all()
    total_marks = 0
    total_credits = 0
    
    for subject in subjects:
        mark = subject.gpa * subject.credit_hours()
        total_marks += mark
        total_credits += subject.credit_hours()

    if total_credits == 0:
        return 0
    return round(total_marks / total_credits, 2)


def calc_cgpa(user):
    subjects = Enrollment.query.filter_by(user_id=user.id).all()
    total_marks = 0
    total_credits = 0
    
    for subject in subjects:
        mark = subject.gpa * subject.credit_hours()
        total_marks += mark
        total_credits += subject.credit_hours()

    if total_credits == 0:
        return 0
    return round(total_marks / total_credits, 2)




#homepage
@gpa_bp.route("/<int:user_id>", methods=["GET", "POST"])
def calc_home(user_id):
    from app import User
    user = User.query.get_or_404(user_id)

    if request.method == "GET":
        subject_list = Enrollment.query.filter_by(user_id=user.id, semester=user.current_semester).all()
        current_gpa = calc_gpa(user)
        current_cgpa = calc_cgpa(user)
        return render_template("gpa.html", subjects=subject_list, gpa=current_gpa, cgpa=current_cgpa, user=user)
    
    elif request.method == "POST":
        subject_id = int(request.form.get('subject_id'))
        subject_gpa = float(request.form.get('subject_gpa'))
        subject = Enrollment.query.get(subject_id)
        subject.gpa = subject_gpa
        assignmenet_db.session.commit()
        return redirect(url_for('gpa.calc_home', user_id=user.id))

# delete subject
# @gpa_bp.route("/delete/<int:subject_id>", methods=["POST"])
# def delete_subject(subject_id):
#     subject = Enrollment.query.get_or_404(subject_id)
#     assignmenet_db.session.delete(subject)
#     assignmenet_db.session.commit()
#     return redirect(url_for('gpa.calc_home'))

# edit subject
# @gpa_bp.route("/edit/<int:subject_id>", methods=["GET", "POST"])
# def edit_subject(subject_id):
#     subject = Enrollment.query.get_or_404(subject_id)
#     if request.method == "POST":
#         subject.name = request.form.get('subject_name').title()
#         subject.gpa = float(request.form.get('subject_gpa'))
#         subject.credits = int(request.form.get('subject_credits'))
#         assignmenet_db.session.commit()
#         return redirect(url_for('gpa.calc_home'))
#     elif request.method == "GET":
#         return render_template("edit.html", subject=subject)
