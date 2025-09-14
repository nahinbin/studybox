from flask import Flask, render_template, redirect, request, url_for
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)

DIR = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(DIR, "gpa.db")

app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"

db = SQLAlchemy(app)

class Subjects(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(50), nullable = False)
    gpa = db.Column(db.Float, default = 0)
    credits = db.Column(db.Integer)

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
@app.route("/", methods=["GET", "POST"])
def calc_home():
    if request.method == "GET":
        subject_list = Subjects.query.all()
        current_gpa = calc_gpa()
        return render_template("gpa.html", subjects = subject_list, gpa = current_gpa)
    elif request.method == "POST":
        new_subject = request.form.get('subject_name')
        subject_gpa = float(request.form.get('subject_gpa'))
        subject_credits = int(request.form.get('subject_credits'))
        subject = Subjects(name = new_subject, gpa = subject_gpa, credits = subject_credits)
        db.session.add(subject)
        db.session.commit()
        return redirect (url_for('calc_home'))
            


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)