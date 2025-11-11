
from flask import (
    Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, SelectField, DateField, FileField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os

# --- App & Config ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-change-me'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'app.db')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'txt'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    tasks = db.relationship('Task', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    notes = db.Column(db.Text, default='', nullable=False)
    priority = db.Column(db.String(20), default='normal', nullable=False)  # low/normal/high
    due_date = db.Column(db.Date, nullable=True)
    done = db.Column(db.Boolean, default=False, nullable=False)
    attachment = db.Column(db.String(255), nullable=True)  # filename
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Forms ---
class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Create account')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember me')
    submit = SubmitField('Log in')

class TaskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    notes = TextAreaField('Notes')
    priority = SelectField('Priority', choices=[('low','Low'),('normal','Normal'),('high','High')], default='normal')
    due_date = DateField('Due date', format='%Y-%m-%d', validators=[], default=None)
    attachment = FileField('Attachment (png/jpg/pdf/txt)')
    submit = SubmitField('Save')

# --- Utils ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- CLI helper to init DB (optional) ---
@app.cli.command('init-db')
def init_db_command():
    db.create_all()
    print('Database initialized.')

# --- Auth Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data.lower()).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))
        user = User(email=form.email.data.lower())
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('auth/register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Welcome back!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.', 'error')
    return render_template('auth/login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'success')
    return redirect(url_for('login'))

# --- Task Routes ---
@app.route('/')
@login_required
def dashboard():
    # Filters & search
    q = request.args.get('q', '').strip()
    status = request.args.get('status', 'all')   # all/open/done
    priority = request.args.get('priority', 'all')
    page = int(request.args.get('page', 1))
    per_page = 5

    query = Task.query.filter_by(user_id=current_user.id)

    if q:
        like = f"%{q}%"
        query = query.filter(db.or_(Task.title.ilike(like), Task.notes.ilike(like)))
    if status == 'open':
        query = query.filter_by(done=False)
    elif status == 'done':
        query = query.filter_by(done=True)
    if priority in {'low','normal','high'}:
        query = query.filter_by(priority=priority)

    query = query.order_by(Task.created_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    tasks = pagination.items

    return render_template('tasks/index.html',
                           tasks=tasks, pagination=pagination,
                           q=q, status=status, priority=priority)

@app.route('/task/new', methods=['GET', 'POST'])
@login_required
def task_new():
    form = TaskForm()
    if form.validate_on_submit():
        filename = None
        file = request.files.get('attachment')
        if file and file.filename:
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            else:
                flash('File type not allowed.', 'error')
                return redirect(url_for('task_new'))
        task = Task(
            title=form.title.data.strip(),
            notes=form.notes.data.strip() if form.notes.data else '',
            priority=form.priority.data,
            due_date=form.due_date.data,
            attachment=filename,
            owner=current_user
        )
        db.session.add(task)
        db.session.commit()
        flash('Task created!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('tasks/edit.html', form=form, mode='new')

@app.route('/task/<int:task_id>/edit', methods=['GET', 'POST'])
@login_required
def task_edit(task_id):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first_or_404()
    form = TaskForm(obj=task)
    if form.validate_on_submit():
        file = request.files.get('attachment')
        if file and file.filename:
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                task.attachment = filename
            else:
                flash('File type not allowed.', 'error')
                return redirect(url_for('task_edit', task_id=task.id))

        task.title = form.title.data.strip()
        task.notes = form.notes.data.strip() if form.notes.data else ''
        task.priority = form.priority.data
        task.due_date = form.due_date.data
        db.session.commit()
        flash('Task updated!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('tasks/edit.html', form=form, mode='edit', task=task)

@app.route('/task/<int:task_id>/toggle')
@login_required
def task_toggle(task_id):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first_or_404()
    task.done = not task.done
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/task/<int:task_id>/delete')
@login_required
def task_delete(task_id):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first_or_404()
    db.session.delete(task)
    db.session.commit()
    flash('Task deleted.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/download/<path:filename>')
@login_required
def download(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# --- Minimal JSON API (must be logged in) ---
@app.route('/api/tasks')
@login_required
def api_tasks():
    items = Task.query.filter_by(user_id=current_user.id).order_by(Task.created_at.desc()).all()
    return jsonify([{
        'id': t.id,
        'title': t.title,
        'notes': t.notes,
        'priority': t.priority,
        'due_date': t.due_date.isoformat() if t.due_date else None,
        'done': t.done,
        'attachment': t.attachment,
        'created_at': t.created_at.isoformat(),
    } for t in items])

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

# --- Bootstrap DB on first run ---
with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
