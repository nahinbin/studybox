from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
#initialize the app
app = Flask(__name__)

#configure the databases(actually start sqlalchemy)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
tracker_db = SQLAlchemy(app)

#database 1
class Subject(tracker_db.Model):
    id = tracker_db.Column(tracker_db.Integer, primary_key=True)
    name = tracker_db.Column(tracker_db.String(100))
    assignments = tracker_db.relationship('Assignment', backref='subject', lazy=True)

#database 2
class Assignment(tracker_db.Model):
    id = tracker_db.Column(tracker_db.Integer, primary_key=True)
    assignment = tracker_db.Column(tracker_db.String(100))
    deadline = tracker_db.Column(tracker_db.Date)
    done = tracker_db.Column(tracker_db.Boolean, default=False)
    linking_dbs = tracker_db.Column(tracker_db.Integer, tracker_db.ForeignKey('subject.id'))

#add assignment/subject
@app.route("/assignment_tracker", methods=["GET", "POST"])
def assignments():
    if request.method == "POST":
        if 'subject_name' in request.form:
            new_subject = request.form.get('subject_name').title()
            subject = Subject(name = new_subject)
            tracker_db.session.add(subject)
            tracker_db.session.commit()
            return redirect('/assignment_tracker')
        elif 'assignment_name' in request.form and 'deadline' in request.form:
            assignment_name = request.form.get('assignment_name')
            deadline_str = request.form.get('deadline')
            deadline = datetime.strptime(deadline_str, '%Y-%m-%d').date()
            done = request.form.get('done')
            subject_id = request.form.get('subject_id')
            assignment = Assignment(assignment=assignment_name, deadline=deadline, done=bool(done), linking_dbs=subject_id)
            tracker_db.session.add(assignment)
            tracker_db.session.commit()
            return redirect('/assignment_tracker')
        elif 'assignment_id' in request.form:
            assignment_id = request.form.get('assignment_id')
            done = request.form.get('done')
            done = True if request.form.get('done') == 'True' else False
            assignment = Assignment.query.get(assignment_id)
            assignment.done = bool(done)
            tracker_db.session.commit()
            return redirect('/assignment_tracker')
        
    elif request.method == "GET":
        assignments = Assignment.query.all()
        subjects = Subject.query.all()
        return render_template("assignments.html", assignments=assignments, subjects=subjects)
#edit assignment
@app.route("/assignment_tracker/edit/<int:id>", methods=["GET", "POST"])
def edit(id):
    assignment = Assignment.query.get_or_404(id)

    if request.method == "POST":
        assignment.assignment = request.form['assignment']
        assignment.deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d').date()
        tracker_db.session.commit()
        return redirect("/assignment_tracker")

    # GET request → show the edit page
    return render_template("edit_assignment.html", assignment=assignment)

#delete assignment
@app.route("/assignment_tracker/delete/<int:id>", methods=["POST"])
def delete(id:int):
    object = Assignment.query.get_or_404(id)
    try:
        tracker_db.session.delete(object)
        tracker_db.session.commit()
        return redirect("/assignment_tracker")
    except Exception as e:
            return f"ERROR: {e}"

#edit subject
@app.route("/assignment_tracker/edit_subject/<int:subject_id>", methods=["POST"])
def edit_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    subject.name = request.form['subject_name'].title()
    tracker_db.session.commit()
    return redirect('/assignment_tracker')

#delete subject
@app.route("/assignment_tracker/delete_subject/<int:subject_id>", methods=["POST"])
def delete_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    tracker_db.session.delete(subject)
    tracker_db.session.commit()
    return redirect('/assignment_tracker')

#run the app
if __name__ == "__main__":
    with app.app_context():
        tracker_db.create_all()
    app.run(debug=True)
