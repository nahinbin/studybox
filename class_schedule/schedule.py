from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from extensions import assignmenet_db
from datetime import datetime

# Import enrollment data to resolve subject names
from subject_enrollment.subject import subjects_info, Enrollment


schedule_bp = Blueprint(
    "schedule",
    __name__,
    url_prefix="/schedule",
    template_folder="templates",
    static_folder="static",
)


class ClassSchedule(assignmenet_db.Model):
    __tablename__ = "class_schedule"
    id = assignmenet_db.Column(assignmenet_db.Integer, primary_key=True)
    user_id = assignmenet_db.Column(
        assignmenet_db.Integer, assignmenet_db.ForeignKey("user.id"), nullable=False
    )
    course_code = assignmenet_db.Column(assignmenet_db.String(100), nullable=False)
    day_of_week = assignmenet_db.Column(assignmenet_db.String(10), nullable=False)
    start_time = assignmenet_db.Column(assignmenet_db.Time, nullable=False)
    end_time = assignmenet_db.Column(assignmenet_db.Time, nullable=True)
    venue = assignmenet_db.Column(assignmenet_db.String(120), nullable=True)
    class_type = assignmenet_db.Column(assignmenet_db.String(20), nullable=True)  # 'Lecture' or 'Tutorial'

    def subject_name(self):
        # Prefer user's custom short name from schedule-only prefs
        pref = ScheduleSubjectPref.query.filter_by(user_id=self.user_id, course_code=self.course_code).first()
        if pref and pref.short_name:
            return pref.short_name
        # Otherwise show the full subject name by default
        return subjects_info.get(self.course_code, {}).get("name", self.course_code)


class ScheduleSubjectPref(assignmenet_db.Model):
    __tablename__ = "schedule_subject_pref"
    id = assignmenet_db.Column(assignmenet_db.Integer, primary_key=True)
    user_id = assignmenet_db.Column(assignmenet_db.Integer, assignmenet_db.ForeignKey("user.id"), nullable=False)
    course_code = assignmenet_db.Column(assignmenet_db.String(100), nullable=False)
    short_name = assignmenet_db.Column(assignmenet_db.String(100), nullable=True)


def _weekday_today():
    # Monday, Tuesday, etc.
    return datetime.now().strftime("%A")


@schedule_bp.route("/", methods=["GET"])
@login_required
def schedule_home():
    # Show enrolled subjects as cards
    enrolled = (
        Enrollment.query.filter_by(user_id=current_user.id).all()
        if current_user.is_authenticated
        else []
    )

    # Today's classes: filter by weekday and order by start_time
    today_name = _weekday_today()
    todays = (
        ClassSchedule.query.filter_by(user_id=current_user.id, day_of_week=today_name)
        .order_by(ClassSchedule.start_time.asc())
        .all()
    )
    
    # Weekly view data
    view = (request.args.get("view") or "daily").lower()
    if view not in ("daily", "weekly"):
        view = "daily"

    days = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]
    weekly_entries = (
        ClassSchedule.query.filter_by(user_id=current_user.id)
        .order_by(ClassSchedule.start_time.asc())
        .all()
    )
    # Collect distinct start times as rows
    times_sorted = sorted({e.start_time for e in weekly_entries})
    # Determine which days have entries
    active_days = [d for d in days if any(e.day_of_week == d for e in weekly_entries)]
    # Build grid: {day: {time: [entries]}} for active days only
    grid = {d: {t: [] for t in times_sorted} for d in active_days}
    for e in weekly_entries:
        if e.start_time in grid.get(e.day_of_week, {}):
            grid[e.day_of_week][e.start_time].append(e)

    return render_template(
        "schedule_home.html",
        enrolled=enrolled,
        todays=todays,
        today_name=today_name,
        view=view,
        days=active_days,
        times_sorted=times_sorted,
        grid=grid,
    )


@schedule_bp.post("/delete/<int:entry_id>")
@login_required
def delete_entry(entry_id):
    entry = ClassSchedule.query.filter_by(id=entry_id, user_id=current_user.id).first()
    if not entry:
        flash("Entry not found.", "warning")
        return redirect(url_for("schedule.schedule_home"))
    assignmenet_db.session.delete(entry)
    assignmenet_db.session.commit()
    flash("Class removed.", "success")
    return redirect(url_for("schedule.schedule_home"))


@schedule_bp.route("/subject/<string:course_code>", methods=["GET", "POST"])
@login_required
def subject_detail(course_code):
    # Ensure user is enrolled in this subject
    enrollment = Enrollment.query.filter_by(user_id=current_user.id, course_code=course_code).first()
    if not enrollment:
        flash("You are not enrolled in this subject.", "warning")
        return redirect(url_for("schedule.schedule_home"))

    if request.method == "POST":
        day_of_week = request.form.get("day_of_week", "").strip()
        start_time_str = request.form.get("start_time", "").strip()
        end_time_str = request.form.get("end_time", "").strip()
        venue = request.form.get("venue", "").strip()
        class_type = request.form.get("class_type", "").strip() or None

        try:
            start_time = datetime.strptime(start_time_str, "%H:%M").time()
        except ValueError:
            flash("Start time must be in HH:MM (24h) format.", "error")
            return redirect(url_for("schedule.subject_detail", course_code=course_code))

        end_time = None
        if end_time_str:
            try:
                end_time = datetime.strptime(end_time_str, "%H:%M").time()
            except ValueError:
                flash("End time must be in HH:MM (24h) format.", "error")
                return redirect(url_for("schedule.subject_detail", course_code=course_code))

        entry = ClassSchedule(
            user_id=current_user.id,
            course_code=course_code,
            day_of_week=day_of_week,
            start_time=start_time,
            end_time=end_time,
            venue=venue or None,
            class_type=class_type,
        )
        assignmenet_db.session.add(entry)
        assignmenet_db.session.commit()
        flash("Session added.", "success")
        return redirect(url_for("schedule.subject_detail", course_code=course_code))

    sessions = (
        ClassSchedule.query.filter_by(user_id=current_user.id, course_code=course_code)
        .order_by(ClassSchedule.day_of_week.asc(), ClassSchedule.start_time.asc())
        .all()
    )
    subject_title = subjects_info.get(course_code, {}).get("name", course_code)
    current_pref = ScheduleSubjectPref.query.filter_by(user_id=current_user.id, course_code=course_code).first()
    return render_template("schedule_subject.html", course_code=course_code, subject_title=subject_title, sessions=sessions, short_name=(current_pref.short_name if current_pref else None))


@schedule_bp.post("/subject/<string:course_code>/short")
@login_required
def set_short_name(course_code):
    # Ensure user is enrolled
    if not Enrollment.query.filter_by(user_id=current_user.id, course_code=course_code).first():
        flash("You are not enrolled in this subject.", "warning")
        return redirect(url_for("schedule.schedule_home"))
    short_name = (request.form.get("short_name") or "").strip()
    pref = ScheduleSubjectPref.query.filter_by(user_id=current_user.id, course_code=course_code).first()
    if not pref:
        pref = ScheduleSubjectPref(user_id=current_user.id, course_code=course_code)
        assignmenet_db.session.add(pref)
    pref.short_name = short_name or None
    assignmenet_db.session.commit()
    flash("Short form updated.", "success")
    return redirect(url_for("schedule.subject_detail", course_code=course_code))

@schedule_bp.post("/subject/<string:course_code>/delete/<int:entry_id>")
@login_required
def delete_subject_entry(course_code, entry_id):
    entry = ClassSchedule.query.filter_by(id=entry_id, user_id=current_user.id, course_code=course_code).first()
    if not entry:
        flash("Entry not found.", "warning")
        return redirect(url_for("schedule.subject_detail", course_code=course_code))
    assignmenet_db.session.delete(entry)
    assignmenet_db.session.commit()
    flash("Session removed.", "success")
    return redirect(url_for("schedule.subject_detail", course_code=course_code))


