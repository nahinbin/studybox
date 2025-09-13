from flask import Flask, render_template, redirect, request
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///gpa.db"

db = SQLAlchemy(app)

class subjects(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(50), )
    gpa = db.Column(db.Integer)



#homepage
@app.route("/", methods=["GET", "POST"])
def calc_home():
    if request.method == "GET":
        subject_list = subjects.query.all()
        return render_template("gpa.html", subject = subject_list)
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)