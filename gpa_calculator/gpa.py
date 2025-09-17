from flask import Flask, render_template, redirect, request, url_for, Blueprint
from flask_sqlalchemy import SQLAlchemy
import os


DIR = os.path.abspath(os.path.dirname(__file__))
templates_dir = os.path.join(DIR, "templates")

DIR = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(DIR, "gpa.db")

static_dir = os.path.join(DIR, "static")


gpa_bp = Blueprint("gpa", __name__, template_folder="templates", static_folder="static")

gpa_db = SQLAlchemy()

class Subjects(gpa_db.Model):
    id = gpa_db.Column(gpa_db.Integer, primary_key = True)
    name = gpa_db.Column(gpa_db.String(50), nullable = False)
    gpa = gpa_db.Column(gpa_db.Float, default = 0)
    credits = gpa_db.Column(gpa_db.Integer)

# function to calculate gpa
def calc_gpa():
    subjects = Subjects.query.all()
    total_marks = 0
    total_credits = 0
    for subject in subjects:
        mark = subject.gpa * subject.credits
        total_marks += mark
        total_credits += subject.credits
    if total_credits == 0:
        return 0
    gpa = round(total_marks/total_credits, 2)
    
    return gpa if gpa else 0

#homepage
@gpa_bp.route("/gpa", methods=["GET", "POST"])
def calc_home():
    if request.method == "GET":
        subject_list = Subjects.query.all()
        current_gpa = calc_gpa()
        return render_template("gpa.html", subjects = subject_list, gpa = current_gpa)
    elif request.method == "POST":
        new_subject = request.form.get('subject_name')
        subject_gpa = float(request.form.get('subject_gpa'))
        subject_credits = int(request.form.get('subject_credits'))
        subject = Subjects(name = (new_subject).title(), gpa = subject_gpa, credits = subject_credits)
        gpa_db.session.add(subject)
        gpa_db.session.commit()
        return redirect (url_for('gpa.calc_home'))
            
# delete subject
@gpa_bp.route("/delete/<int:subject_id>", methods=["POST"])
def delete_subject(subject_id):
    subject = Subjects.query.get_or_404(subject_id)
    gpa_db.session.delete(subject)
    gpa_db.session.commit()
    return redirect(url_for('gpa.calc_home'))

@gpa_bp.route("/edit/<int:subject_id>", methods=["GET", "POST"])
def edit_subject(subject_id):
    subject = Subjects.query.get_or_404(subject_id)
    if request.method == "POST":
        subject.name = request.form.get('subject_name').title()
        subject.gpa = float(request.form.get('subject_gpa'))
        subject.credits = int(request.form.get('subject_credits'))
        gpa_db.session.commit()
        return redirect(url_for('gpa.calc_home'))
    return render_template("edit.html", subject=subject)
