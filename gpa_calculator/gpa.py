from flask import Flask, render_template, redirect, request, url_for, Blueprint
import os
from extensions import assignmenet_db
from subject_enrollment.subject import Enrollment, sem_dic, PreviousSemester
from tracker.task_tracker import Assignment
# Avoid importing User at module scope to prevent circular import

DIR = os.path.abspath(os.path.dirname(__file__))
templates_dir = os.path.join(DIR, "templates")
static_dir = os.path.join(DIR, "static")


gpa_bp = Blueprint("gpa", __name__, template_folder=f"{templates_dir}", static_folder=f"{static_dir}")



def get_missed_sem(user_id):
    from app import User
    user = User.query.get_or_404(user_id)
    current_semester = user.current_semester
    
    # Get the semester order as a list
    semester_order = list(sem_dic.keys())  
    
    # If user has no current semester (graduated or not enrolled), return empty list
    if current_semester is None:
        return []
    
    # If user is in first semester, no missed semesters
    if current_semester == 'First Semester':
        return []
    
    # Get completed semesters from database
    completed_semesters = PreviousSemester.query.filter_by(user_id=user_id).all()
    completed_semester_names = [sem.name for sem in completed_semesters]
    
    # Find current semester index
    current_index = semester_order.index(current_semester)
    
    
    # Get all semesters that should be completed before current
    required_semesters = semester_order[:current_index]
    
    # Find missing semesters
    missed_semesters = [sem for sem in required_semesters if sem not in completed_semester_names]
    
    return missed_semesters

def weighted_score(enrollment: Enrollment):
    tasks = Assignment.query.filter_by(enrollment_id=enrollment.id).all()
    if not tasks:
        return 0.0
    total_weight = 0.0
    weighted_sum = 0.0
    for t in tasks:
        weight = t.weight if t.weight is not None else 1.0
        if t.score is None:
            continue
        total_weight += weight
        weighted_sum += (float(t.score) / 100.0) * weight
    if total_weight == 0.0:
        return 0.0
    return float(weighted_sum / total_weight)


def average_score(enrollment: Enrollment):
    tasks = Assignment.query.filter_by(enrollment_id=enrollment.id).all()
    graded = [t for t in tasks if t.score and t.max_score]
    if not graded:
        return 0.0
    # Calculate weighted average where each task contributes its percentage of total grade
    total_weighted_score = 0.0
    total_weight = 0.0
    for t in graded:
        w = float(t.weight) if t.weight is not None else 1.0
        # Calculate percentage score for this task (score/max_score gives percentage)
        task_percentage = float(t.score) / float(t.max_score)
        # Add weighted contribution
        total_weighted_score += task_percentage * w
        total_weight += w
    if total_weight == 0.0:
        return 0.0
    return float(total_weighted_score / total_weight)


def calc_gpa(user):
    all_enrollments = Enrollment.query.filter_by(user_id=user.id).all()
    current_codes = sem_dic.get(user.current_semester, [])
    subjects = [en for en in all_enrollments if en.course_code in current_codes]
    
    # Get all tasks from current semester subjects
    all_tasks = []
    for subject in subjects:
        tasks = Assignment.query.filter_by(enrollment_id=subject.id).all()
        all_tasks.extend(tasks)
    
    if not all_tasks:
        return 0
    
    # Calculate GPA based on individual task marks
    total_weight = 0.0
    weighted_sum = 0.0
    
    for task in all_tasks:
        if task.score is not None and task.max_score is not None:
            weight = task.weight if task.weight is not None else 1.0
            # Calculate percentage score for this task
            task_percentage = float(task.score) / float(task.max_score)
            # Add weighted contribution
            weighted_sum += task_percentage * weight
            total_weight += weight
    
    if total_weight == 0.0:
        return 0
    
    # Convert to 4.0 scale
    gpa = (weighted_sum / total_weight) * 4.0
    return round(gpa, 2)


def calc_cgpa(user):
    subjects = Enrollment.query.filter_by(user_id=user.id).all()
    total_marks = 0.0
    total_credits = 0
    
    for subject in subjects:
        ratio = average_score(subject)
        subject_gpa = 4.0 * ratio
        total_marks += subject_gpa * subject.credit_hours()
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
        all_enrollments = Enrollment.query.filter_by(user_id=user.id).all()
        current_codes = sem_dic.get(user.current_semester, [])
        subject_list = [en for en in all_enrollments if en.course_code in current_codes]
        current_gpa = calc_gpa(user)
        current_cgpa = calc_cgpa(user)
        
        # Calculate partial GPA data for each subject
        subjects_with_data = []
        for subject in subject_list:
            tasks = Assignment.query.filter_by(enrollment_id=subject.id).all()
            if not tasks:
                partial_data = {"gpa": 0.0, "completion": 0.0, "completed_tasks": 0, "total_tasks": 0}
            else:
                total_weight = 0.0
                completed_weight = 0.0
                weighted_sum = 0.0
                completed_tasks = 0
                
                for t in tasks:
                    weight = t.weight if t.weight is not None else 1.0
                    total_weight += weight
                    
                    if t.score is not None and t.max_score is not None:
                        completed_weight += weight
                        task_percentage = float(t.score) / float(t.max_score)
                        weighted_sum += task_percentage * weight
                        completed_tasks += 1
                
                if completed_weight == 0.0:
                    partial_data = {"gpa": 0.0, "completion": 0.0, "completed_tasks": 0, "total_tasks": len(tasks)}
                else:
                    # Calculate GPA (0-4 scale)
                    percentage = weighted_sum / completed_weight
                    gpa = percentage * 4.0
                    
                    # Calculate completion percentage
                    completion = (completed_weight / total_weight) * 100.0
                    
                    partial_data = {
                        "gpa": round(gpa, 2),
                        "completion": round(completion, 1),
                        "completed_tasks": completed_tasks,
                        "total_tasks": len(tasks)
                    }
            
            subjects_with_data.append({
                'subject': subject,
                'partial_data': partial_data
            })
        
        # Get missed semesters
        missed_semesters = get_missed_sem(user.id)
        
        return render_template("gpa.html", 
                             subjects_with_data=subjects_with_data, 
                             gpa=current_gpa, 
                             cgpa=current_cgpa, 
                             user=user,
                             missed_semesters=missed_semesters)
    
    elif request.method == "POST":
        if request.form.get('update_task_score') and request.form.get('task_id'):
            task_id = int(request.form.get('task_id'))
            score_val = request.form.get('score')
            max_score_val = request.form.get('max_score')
            task = Assignment.query.get(task_id)
            task.score = float(score_val) if score_val not in (None, "") else None
            task.max_score = float(max_score_val) if max_score_val not in (None, "") else None
            assignmenet_db.session.commit()
        elif request.form.get('add_previous_gpa'):
            # Handle previous semester GPA entry
            from subject_enrollment.subject import PreviousSemester
            semester_name = request.form.get('semester_name')
            gpa = float(request.form.get('gpa'))
            
            # Create a new PreviousSemester entry
            previous_sem = PreviousSemester(
                name=semester_name,
                user_id=user.id
            )
            assignmenet_db.session.add(previous_sem)
            assignmenet_db.session.commit()
        return redirect(url_for('gpa.calc_home', user_id=user.id))


