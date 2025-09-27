from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from urllib.parse import urlparse

from extensions import db
from database import QuickLink


quicklinks_bp = Blueprint('quicklinks', __name__)


def _get_favicon_url(url: str) -> str | None:
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        if not domain:
            return None
        return f"https://www.google.com/s2/favicons?domain={domain}&sz=32"
    except Exception:
        return None


@quicklinks_bp.route('/quicklinks', endpoint='quicklinks')
@login_required
def quicklinks():
    links = QuickLink.query.filter_by(user_id=current_user.id).order_by(QuickLink.created_at.desc()).all()

    mmu_links = []
    try:
        if current_user.email and current_user.email.endswith('@student.mmu.edu.my'):
            _mmu_links_data = [
                { 'title': 'MMU Portal', 'url': 'https://portal.mmu.edu.my', 'description': 'Main student portal', 'display_order': 1 },
                { 'title': 'Student Email', 'url': 'https://mail.mmu.edu.my', 'description': 'Access your MMU email', 'display_order': 2 },
                { 'title': 'MMU CLiC', 'url': 'https://clic.mmu.edu.my', 'description': 'Course Learning & Information Center', 'display_order': 3 },
                { 'title': 'eBwise', 'url': 'https://ebwise.mmu.edu.my', 'description': 'MMU eBwise portal', 'display_order': 4 },
                { 'title': 'Library System', 'url': 'https://library.mmu.edu.my', 'description': 'MMU digital library', 'display_order': 5 },
                { 'title': 'Academic Calendar', 'url': 'https://www.mmu.edu.my/academic-calendar', 'description': 'Important dates and events', 'display_order': 6 },
            ]
            for item in _mmu_links_data:
                item['favicon_url'] = _get_favicon_url(item['url']) or f"https://www.google.com/s2/favicons?domain={item['url']}&sz=32"
            mmu_links = sorted(_mmu_links_data, key=lambda x: x.get('display_order', 0))
    except Exception:
        mmu_links = []

    return render_template('quicklinks.html', links=links, mmu_links=mmu_links)


@quicklinks_bp.route('/quicklinks/add', methods=['GET', 'POST'], endpoint='add_quicklink')
@login_required
def add_quicklink():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        url = request.form.get('url', '').strip()
        description = request.form.get('description', '').strip()

        if not title or not url:
            flash('Title and URL are required')
            return redirect(url_for('quicklinks'))

        favicon_url = _get_favicon_url(url)

        new_link = QuickLink(
            title=title,
            url=url,
            favicon_url=favicon_url,
            description=description,
            user_id=current_user.id
        )

        db.session.add(new_link)
        db.session.commit()

        flash('Quick link added successfully!')
        return redirect(url_for('quicklinks.quicklinks'))

    return render_template('add_quicklink.html')


@quicklinks_bp.route('/quicklinks/delete/<int:link_id>', methods=['POST'], endpoint='delete_quicklink')
@login_required
def delete_quicklink(link_id: int):
    link = QuickLink.query.filter_by(id=link_id, user_id=current_user.id).first()
    if link:
        db.session.delete(link)
        db.session.commit()
        flash('Quick link deleted successfully!')
    else:
        flash('Quick link not found')
    return redirect(url_for('quicklinks.quicklinks'))


@quicklinks_bp.route('/quicklinks/delete-all', methods=['POST'], endpoint='delete_all_quicklinks')
@login_required
def delete_all_quicklinks():
    try:
        QuickLink.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        return {'success': True}, 200
    except Exception as e:
        db.session.rollback()
        return {'success': False, 'error': str(e)}, 500


@quicklinks_bp.route('/quicklinks/delete-selected', methods=['POST'], endpoint='delete_selected_quicklinks')
@login_required
def delete_selected_quicklinks():
    try:
        data = request.get_json()
        link_ids = data.get('link_ids', [])

        if not link_ids:
            return {'success': False, 'error': 'No links selected'}, 400

        QuickLink.query.filter(
            QuickLink.id.in_(link_ids),
            QuickLink.user_id == current_user.id
        ).delete(synchronize_session=False)

        db.session.commit()
        return {'success': True}, 200
    except Exception as e:
        db.session.rollback()
        return {'success': False, 'error': str(e)}, 500


