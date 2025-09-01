from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
#initialize the app
app = Flask(__name__)

#configure the databases(actually start sqlalchemy)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
database = SQLAlchemy(app)

#database 1
class Subject(database.Model):
    id = database.Column(database.Integer, primary_key=True)
    name = database.Column(database.String(100))
    assignments = database.relationship('Assignment', backref='subject', lazy=True)

#database 2
class Assignment(database.Model):
    id = database.Column(database.Integer, primary_key=True)
    assignment = database.Column(database.String(100))
    deadline = database.Column(database.Date)
    done = database.Column(database.Boolean, default=False)
    linking_dbs = database.Column(database.Integer, database.ForeignKey('subject.id'))

#add assignment/subject
@app.route("/", methods=["GET", "POST"])
def assignments():
    if request.method == "POST":
        if 'subject_name' in request.form:
            new_subject = request.form.get('subject_name').title()
            subject = Subject(name = new_subject)
            database.session.add(subject)
            database.session.commit()
            return redirect('/')
        elif 'assignment_name' in request.form and 'deadline' in request.form:
            assignment_name = request.form.get('assignment_name')
            deadline_str = request.form.get('deadline')
            deadline = datetime.strptime(deadline_str, '%Y-%m-%d').date()
            done = request.form.get('done')
            subject_id = request.form.get('subject_id')
            assignment = Assignment(assignment=assignment_name, deadline=deadline, done=bool(done), linking_dbs=subject_id)
            database.session.add(assignment)
            database.session.commit()
            return redirect('/')
        elif 'assignment_id' in request.form:
            assignment_id = request.form.get('assignment_id')
            done = request.form.get('done')
            done = True if request.form.get('done') == 'True' else False
            assignment = Assignment.query.get(assignment_id)
            assignment.done = bool(done)
            database.session.commit()
            return redirect('/')
        
    elif request.method == "GET":
        assignments = Assignment.query.all()
        subjects = Subject.query.all()
        return render_template("assignments.html", assignments=assignments, subjects=subjects)
#edit assignment
@app.route("/edit/<int:id>", methods=["GET", "POST"])
def edit(id):
    assignment = Assignment.query.get_or_404(id)

    if request.method == "POST":
        assignment.assignment = request.form['assignment']
        assignment.deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d').date()
        database.session.commit()
        return redirect("/")

    # GET request → show the edit page
    return render_template("edit.html", assignment=assignment)

#delete assignment
@app.route("/delete/<int:id>", methods=["POST"])
def delete(id:int):
    object = Assignment.query.get_or_404(id)
    try:
        database.session.delete(object)
        database.session.commit()
        return redirect("/")
    except Exception as e:
            return f"ERROR: {e}"

#edit subject
@app.route("/edit_subject/<int:subject_id>", methods=["POST"])
def edit_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    subject.name = request.form['subject_name'].title()
    database.session.commit()
    return redirect('/')

#delete subject
@app.route("/delete_subject/<int:subject_id>", methods=["POST"])
def delete_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    database.session.delete(subject)
    database.session.commit()
    return redirect('/')

#run the app
if __name__ == "__main__":
    with app.app_context():
        database.create_all()
    app.run(debug=True)
