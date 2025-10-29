from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, send_file
from flask_login import login_required, current_user
from io import BytesIO
import os
from extensions import db
from database import Note
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


notes_bp = Blueprint('notes', __name__, template_folder='templates')


def _wrap_text(text, max_chars=90):
    if not text:
        return [""]
    lines = []
    for paragraph in str(text).splitlines() or [""]:
        words = paragraph.split(' ')
        current = []
        length = 0
        for w in words:
            if length + len(w) + (1 if current else 0) > max_chars:
                lines.append(' '.join(current))
                current = [w]
                length = len(w)
            else:
                current.append(w)
                length += len(w) + (1 if current[:-1] else 0)
        if current:
            lines.append(' '.join(current))
        if not words:
            lines.append("")
    return lines


@notes_bp.route('/notes', methods=['GET'])
@login_required
def list_notes():
    notes = Note.query.filter_by(user_id=current_user.id).order_by(Note.updated_at.desc()).all()
    return render_template('notes_list.html', notes=notes)


@notes_bp.route('/notes/create', methods=['POST'])
@login_required
def create_note():
    title = (request.form.get('title') or '').strip()
    content = (request.form.get('content') or '').strip()
    if not title:
        flash('Title is required.')
        return redirect(url_for('notes.list_notes'))

    note = Note(user_id=current_user.id, title=title, content=content)
    db.session.add(note)
    db.session.commit()
    flash('Note created.')
    return redirect(url_for('notes.list_notes'))


@notes_bp.route('/notes/<int:note_id>', methods=['GET'])
@login_required
def view_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        flash('Not authorized to view this note.')
        return redirect(url_for('notes.list_notes'))
    return render_template('note_detail.html', note=note)


@notes_bp.route('/notes/<int:note_id>/edit', methods=['POST'])
@login_required
def edit_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        flash('Not authorized.')
        return redirect(url_for('notes.list_notes'))

    title = (request.form.get('title') or '').strip()
    content = (request.form.get('content') or '').strip()

    if title:
        note.title = title
    note.content = content

    db.session.commit()
    flash('Note updated.')
    return redirect(url_for('notes.view_note', note_id=note.id))


@notes_bp.route('/notes/<int:note_id>/delete', methods=['POST'])
@login_required
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        flash('Not authorized.')
        return redirect(url_for('notes.list_notes'))
    db.session.delete(note)
    db.session.commit()
    flash('Note deleted.')
    return redirect(url_for('notes.list_notes'))


@notes_bp.route('/notes/<int:note_id>/pdf', methods=['GET'])
@login_required
def export_note_pdf(note_id):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        flash('Not authorized.')
        return redirect(url_for('notes.list_notes'))

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    y = height - 72
    p.setFont("Helvetica-Bold", 16)
    p.drawString(72, y, note.title or "Untitled Note")
    y -= 24
    p.setFont("Helvetica", 11)
    y -= 8
    for line in _wrap_text(note.content or "", max_chars=90):
        if y < 72:
            p.showPage()
            y = height - 72
            p.setFont("Helvetica", 11)
        p.drawString(72, y, line)
        y -= 16

    p.showPage()
    p.save()
    buffer.seek(0)
    filename = f"{(note.title or 'note').strip().replace(' ', '_')}.pdf"
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype='application/pdf')


