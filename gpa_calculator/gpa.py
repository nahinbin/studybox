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
    gpa = db.Column(db.Integer, default = 0)
    credits = db.Column(db.Integer, default = 0)



#homepage
@app.route("/", methods=["GET", "POST"])
def calc_home():
    if request.method == "GET":
        subject_list = Subjects.query.all()
        return render_template("gpa.html", subject = subject_list)
    elif request.method == "POST":
        if "subject_name" in request.form:
            new_subject = request.form.get('subject_name')
            subject = Subjects(name = new_subject)
            db.session.add(subject)
            db.session.commit()
        return redirect (url_for('calc_home'))
            

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)