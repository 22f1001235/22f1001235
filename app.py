from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from functools import wraps
import random
import string

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz_master.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# List of Indian States and Union Territories
INDIAN_STATES = [
    'Andhra Pradesh', 'Arunachal Pradesh', 'Assam', 'Bihar', 'Chhattisgarh',
    'Delhi', 'Goa', 'Gujarat', 'Haryana', 'Himachal Pradesh', 'Jammu and Kashmir',
    'Jharkhand', 'Karnataka', 'Kerala', 'Ladakh', 'Lakshadweep', 'Madhya Pradesh',
    'Maharashtra', 'Manipur', 'Meghalaya', 'Mizoram', 'Nagaland', 'Odisha',
    'Puducherry', 'Punjab', 'Rajasthan', 'Sikkim', 'Tamil Nadu', 'Telangana',
    'Tripura', 'Uttar Pradesh', 'Uttarakhand', 'West Bengal'
]

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    mobile_no = db.Column(db.String(15), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    state = db.Column(db.String(50), nullable=False)
    city = db.Column(db.String(50), nullable=False)
    qualification = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    quiz_attempts = db.relationship('QuizAttempt', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    resource = db.Column(db.Text)
    chapters = db.relationship('Chapter', backref='subject', lazy=True)

class Chapter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapter.id'), nullable=False)
    date_of_quiz = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Integer, nullable=False)  # in minutes
    questions = db.relationship('Question', backref='quiz', lazy=True, cascade='all, delete-orphan')
    attempts = db.relationship('QuizAttempt', backref='quiz', lazy=True)
    chapter = db.relationship('Chapter', backref='quizzes', lazy=True)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    option1 = db.Column(db.String(200), nullable=False)
    option2 = db.Column(db.String(200), nullable=False)
    option3 = db.Column(db.String(200), nullable=False)
    option4 = db.Column(db.String(200), nullable=False)
    correct_option = db.Column(db.Integer, nullable=False)  # 1, 2, 3, or 4
    score = db.Column(db.Integer, nullable=False, default=1)  # Score for this question

class QuizAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    date_attempted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    start_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    score = db.Column(db.Float, nullable=False)
    answers = db.relationship('Answer', backref='attempt', lazy=True)

class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    attempt_id = db.Column(db.Integer, db.ForeignKey('quiz_attempt.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    selected_option = db.Column(db.Integer, nullable=False)  # 1, 2, 3, or 4
    question = db.relationship('Question', backref='answers', lazy=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        password = request.form.get('password')
        user = User.query.filter_by(user_id=user_id).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid User ID or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    subjects = Subject.query.all()
    chapters = Chapter.query.all()
    quizzes = Quiz.query.all()
    
    # Calculate user performance statistics
    total_score = 0
    total_attempts = 0
    passed_attempts = 0
    
    # Get all attempts by non-admin users
    all_attempts = []
    for user in users:
        if not user.is_admin:
            for attempt in user.quiz_attempts:
                all_attempts.append(attempt)
                total_score += attempt.score
                total_attempts += 1
                if attempt.score >= 40:  # Pass threshold
                    passed_attempts += 1
    
    # Calculate average score
    avg_score = total_score / total_attempts if total_attempts > 0 else 0
    
    # Calculate pass rate
    pass_rate = (passed_attempts / total_attempts * 100) if total_attempts > 0 else 0
    
    # Count active users (users with at least one quiz attempt)
    active_users = sum(1 for user in users if not user.is_admin and user.quiz_attempts)
    
    # Calculate subject-wise performance
    subject_performance = {}
    for subject in subjects:
        subject_attempts = []
        for attempt in all_attempts:
            if attempt.quiz.chapter.subject_id == subject.id:
                subject_attempts.append(attempt.score)
        
        if subject_attempts:
            avg_subject_score = sum(subject_attempts) / len(subject_attempts)
            subject_performance[subject.name] = {
                'average_score': round(avg_subject_score, 1),
                'attempts': len(subject_attempts)
            }
    
    return render_template('admin/dashboard.html', 
                          users=users, 
                          subjects=subjects, 
                          chapters=chapters, 
                          quizzes=quizzes,
                          total_attempts=total_attempts,
                          avg_score=avg_score,
                          pass_rate=pass_rate,
                          active_users=active_users,
                          subject_performance=subject_performance)

# Subject Management Routes
@app.route('/admin/subjects')
@login_required
@admin_required
def manage_subjects():
    subjects = Subject.query.all()
    return render_template('admin/manage_subjects.html', subjects=subjects)

@app.route('/admin/subjects/add', methods=['POST'])
@login_required
@admin_required
def add_subject():
    name = request.form.get('name')
    description = request.form.get('description')
    resource = request.form.get('resource')
    
    if not name or not description or not resource:
        flash('All fields are required', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    try:
        subject = Subject(name=name, description=description, resource=resource)
        db.session.add(subject)
        db.session.commit()
        
        flash('Subject added successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding subject: {str(e)}', 'danger')
        print(f"Database error: {str(e)}")
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/subjects/edit', methods=['POST'])
@login_required
@admin_required
def edit_subject():
    subject_id = request.form.get('subject_id')
    name = request.form.get('name')
    description = request.form.get('description')
    resource = request.form.get('resource')
    
    print(f"Editing subject: ID={subject_id}, Name={name}, Desc={description}, Resource={resource}")
    
    if not all([subject_id, name, description, resource]):
        flash('All fields are required', 'danger')
        print(f"Missing fields: subject_id={subject_id}, name={name}, description={description}, resource={resource}")
        return redirect(url_for('admin_dashboard'))
    
    try:
        subject = Subject.query.get_or_404(subject_id)
        print(f"Found subject: {subject.name}")
        
        subject.name = name
        subject.description = description
        subject.resource = resource
        
        db.session.commit()
        print(f"Subject updated successfully: {subject.name}")
        
        flash('Subject updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        error_message = str(e)
        print(f"Database error updating subject: {error_message}")
        flash(f'Error updating subject: {error_message}', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/api/subjects/<int:subject_id>')
@login_required
@admin_required
def get_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    return render_template('admin/api/subject_data.html', subject=subject)

@app.route('/api/subjects/<int:subject_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    db.session.delete(subject)
    db.session.commit()
    return '', 204

# Chapter Management Routes
@app.route('/admin/chapters')
@login_required
@admin_required
def manage_chapters():
    chapters = Chapter.query.all()
    subjects = Subject.query.all()
    return render_template('admin/manage_chapters.html', chapters=chapters, subjects=subjects)

@app.route('/admin/chapters/add', methods=['POST'])
@login_required
@admin_required
def add_chapter():
    subject_id = request.form.get('subject_id')
    name = request.form.get('name')
    description = request.form.get('description')
    
    if not subject_id or not name or not description:
        flash('All fields are required', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    try:
        chapter = Chapter(subject_id=subject_id, name=name, description=description)
        db.session.add(chapter)
        db.session.commit()
        
        flash('Chapter added successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding chapter: {str(e)}', 'danger')
        print(f"Database error: {str(e)}")
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/chapters/edit', methods=['POST'])
@login_required
@admin_required
def edit_chapter():
    chapter_id = request.form.get('chapter_id')
    subject_id = request.form.get('subject_id')
    name = request.form.get('name')
    description = request.form.get('description')
    
    print(f"Editing chapter: ID={chapter_id}, Subject ID={subject_id}, Name={name}, Desc={description}")
    
    if not all([chapter_id, subject_id, name, description]):
        flash('All fields are required', 'danger')
        print(f"Missing fields: chapter_id={chapter_id}, subject_id={subject_id}, name={name}, description={description}")
        return redirect(url_for('admin_dashboard'))
    
    try:
        chapter = Chapter.query.get_or_404(chapter_id)
        print(f"Found chapter: {chapter.name}, original subject_id={chapter.subject_id}")
        
        chapter.subject_id = subject_id
        chapter.name = name
        chapter.description = description
        
        db.session.commit()
        print(f"Chapter updated successfully: {chapter.name}, new subject_id={chapter.subject_id}")
        
        flash('Chapter updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        error_message = str(e)
        print(f"Database error updating chapter: {error_message}")
        flash(f'Error updating chapter: {error_message}', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/api/chapters/<int:chapter_id>')
@login_required
@admin_required
def get_chapter(chapter_id):
    try:
        chapter = Chapter.query.get_or_404(chapter_id)
        return render_template('admin/api/chapter_data.html', chapter=chapter)
    except Exception as e:
        print(f"Error fetching chapter data: {str(e)}")
        return jsonify({'error': 'Failed to fetch chapter data'}), 500

@app.route('/api/chapters/<int:chapter_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_chapter(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    db.session.delete(chapter)
    db.session.commit()
    return '', 204

@app.route('/api/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        return '', 403  # Prevent deleting admin users
    db.session.delete(user)
    db.session.commit()
    return '', 204

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        email = request.form.get('email')
        full_name = request.form.get('full_name')
        mobile_no = request.form.get('mobile_no')
        dob = datetime.strptime(request.form.get('dob'), '%Y-%m-%d').date()
        gender = request.form.get('gender')
        state = request.form.get('state')
        city = request.form.get('city')
        qualification = request.form.get('qualification')
        
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        
        # Create user with initial data
        user = User(
            email=email,
            full_name=full_name,
            mobile_no=mobile_no,
            dob=dob,
            gender=gender,
            state=state,
            city=city,
            qualification=qualification,
            user_id=generate_user_id(email)
        )
        
        # Store user in session for password creation
        session['temp_user_id'] = user.user_id
        db.session.add(user)
        db.session.commit()
        
        return redirect(url_for('create_password'))
    
    return render_template('register.html', states=INDIAN_STATES)

@app.route('/create_password', methods=['GET', 'POST'])
def create_password():
    if 'temp_user_id' not in session:
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('create_password'))
        
        user = User.query.filter_by(user_id=session['temp_user_id']).first()
        if user:
            user.set_password(password)
            db.session.commit()
            
            # Store user_id and password in session for display
            session['registration_complete'] = True
            session['registered_user_id'] = user.user_id
            session['registered_password'] = password
            
            return redirect(url_for('registration_success'))
    
    return render_template('create_password.html')

@app.route('/registration_success')
def registration_success():
    if not session.get('registration_complete'):
        return redirect(url_for('register'))
    
    user_id = session.get('registered_user_id')
    password = session.get('registered_password')
    
    # Clear the session data
    session.pop('registration_complete', None)
    session.pop('registered_user_id', None)
    session.pop('registered_password', None)
    session.pop('temp_user_id', None)
    
    return render_template('registration_success.html', user_id=user_id, password=password)

def generate_user_id(email):
    # Get the part before @ in email
    email_prefix = email.split('@')[0]
    # Generate random 5 digits
    random_digits = ''.join(random.choices(string.digits, k=5))
    # Combine to create user_id
    return f"{email_prefix}_{random_digits}"

def init_db():
    with app.app_context():
        # Create tables if they don't exist without dropping existing data
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(user_id='admin_00000').first()
        if not admin:
            admin = User(
                email='admin@quizmaster.com',
                full_name='Administrator',
                mobile_no='0000000000',
                dob=datetime.now().date(),
                gender='Other',
                state='Delhi',
                city='New Delhi',
                qualification='Admin',
                user_id='admin_00000',
                is_admin=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully!")
        else:
            print("Admin user already exists!")

# User Dashboard Routes
@app.route('/user/dashboard')
@login_required
def user_dashboard():
    subjects = Subject.query.all()
    quiz_attempts = QuizAttempt.query.filter_by(user_id=current_user.id).order_by(QuizAttempt.date_attempted.desc()).all()
    
    # Calculate subject-wise performance
    subject_performance = {}
    for subject in subjects:
        subject_attempts = [attempt for attempt in quiz_attempts if attempt.quiz.chapter.subject_id == subject.id]
        if subject_attempts:
            avg_score = sum(attempt.score for attempt in subject_attempts) / len(subject_attempts)
            subject_performance[subject.name] = {
                'average_score': round(avg_score, 1),
                'attempts': len(subject_attempts)
            }
    
    return render_template('user/dashboard.html', 
                         subjects=subjects, 
                         quiz_attempts=quiz_attempts,
                         subject_performance=subject_performance)

@app.route('/user/subjects/<int:subject_id>/chapters')
@login_required
def view_chapters(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    chapters = Chapter.query.filter_by(subject_id=subject_id).all()
    return render_template('user/chapters.html', subject=subject, chapters=chapters)

@app.route('/user/chapters/<int:chapter_id>/quizzes')
@login_required
def view_quizzes(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    quizzes = Quiz.query.filter_by(chapter_id=chapter_id).all()
    
    # Get attempted quizzes
    attempted_quizzes = [attempt.quiz for attempt in QuizAttempt.query.filter_by(user_id=current_user.id).all()]
    
    # Get available quizzes (not attempted and current date)
    available_quizzes = [quiz for quiz in quizzes if quiz not in attempted_quizzes and quiz.date_of_quiz <= datetime.now()]
    
    return render_template('user/quizzes.html', 
                         chapter=chapter, 
                         quizzes=quizzes,
                         available_quizzes=available_quizzes,
                         attempted_quizzes=attempted_quizzes)

@app.route('/user/quizzes/<int:quiz_id>/take')
@login_required
def take_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    
    # Check if user has already attempted this quiz
    if QuizAttempt.query.filter_by(user_id=current_user.id, quiz_id=quiz_id).first():
        flash('You have already attempted this quiz.', 'warning')
        return redirect(url_for('view_quizzes', chapter_id=quiz.chapter_id))
    
    # Check if quiz is available
    if quiz.date_of_quiz > datetime.now():
        flash('This quiz is not yet available.', 'warning')
        return redirect(url_for('view_quizzes', chapter_id=quiz.chapter_id))
    
    # Create a new quiz attempt with initial score of 0
    attempt = QuizAttempt(
        user_id=current_user.id,
        quiz_id=quiz_id,
        start_time=datetime.utcnow(),
        score=0  # Initialize with 0
    )
    db.session.add(attempt)
    db.session.commit()
    
    return render_template('user/take_quiz.html', quiz=quiz, attempt=attempt)

@app.route('/user/quizzes/<int:quiz_id>/submit', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    
    try:
        # Get the existing attempt
        attempt = QuizAttempt.query.filter_by(user_id=current_user.id, quiz_id=quiz_id).first()
        if not attempt:
            flash('No active quiz attempt found.', 'error')
            return redirect(url_for('view_quizzes', chapter_id=quiz.chapter_id))
        
        # Calculate score
        correct_answers = 0
        total_questions = len(quiz.questions)
        
        # Process answers and calculate score
        for question in quiz.questions:
            answer = request.form.get(f'question_{question.id}')
            selected_option = int(answer) if answer else 0
            
            # Save answer
            answer_record = Answer(
                attempt_id=attempt.id,
                question_id=question.id,
                selected_option=selected_option
            )
            db.session.add(answer_record)
            
            # Only count correct answers if an answer was provided
            if answer and selected_option == question.correct_option:
                correct_answers += 1
        
        # Update the score and set the completion time
        attempt.score = (correct_answers / total_questions) * 100 if total_questions > 0 else 0
        attempt.date_attempted = datetime.utcnow()
        
        # Commit all changes
        db.session.commit()
        return redirect(url_for('quiz_result', attempt_id=attempt.id))
        
    except Exception as e:
        db.session.rollback()
        print(f"Error submitting quiz: {str(e)}")  # Add error logging
        flash(f'Error submitting quiz: {str(e)}', 'error')  # Show actual error to user
        return redirect(url_for('take_quiz', quiz_id=quiz_id))

@app.route('/user/quizzes/attempts/<int:attempt_id>/result')
@login_required
def quiz_result(attempt_id):
    attempt = QuizAttempt.query.get_or_404(attempt_id)
    
    # Ensure user can only view their own attempts
    if attempt.user_id != current_user.id:
        flash('You do not have permission to view this result.', 'error')
        return redirect(url_for('user_dashboard'))
    
    return render_template('user/quiz_result.html', attempt=attempt)

@app.route('/user/quizzes/attempts/<int:attempt_id>/analysis')
@login_required
def view_quiz_analysis(attempt_id):
    attempt = QuizAttempt.query.get_or_404(attempt_id)
    
    # Ensure user can only view their own attempts
    if attempt.user_id != current_user.id:
        flash('You do not have permission to view this analysis.', 'error')
        return redirect(url_for('user_dashboard'))
    
    return render_template('user/quiz_analysis.html', attempt=attempt)

@app.route('/admin/users')
@login_required
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('admin/manage_users.html', users=users)

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.full_name = request.form.get('full_name')
        user.mobile_no = request.form.get('mobile_no')
        user.state = request.form.get('state')
        user.city = request.form.get('city')
        user.qualification = request.form.get('qualification')
        
        # Handle password change if provided
        new_password = request.form.get('new_password')
        if new_password:
            user.set_password(new_password)
        
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('manage_users'))
    
    return render_template('admin/edit_user.html', user=user, states=INDIAN_STATES)

@app.route('/admin/users/<int:user_id>/performance')
@login_required
@admin_required
def view_user_performance(user_id):
    user = User.query.get_or_404(user_id)
    quiz_attempts = QuizAttempt.query.filter_by(user_id=user_id).order_by(QuizAttempt.date_attempted.desc()).all()
    
    # Get subjects and calculate subject-wise performance
    subjects = Subject.query.all()
    subject_performance = {}
    
    # Calculate overall statistics
    total_attempts = len(quiz_attempts)
    average_score = sum(attempt.score for attempt in quiz_attempts) / total_attempts if total_attempts > 0 else 0
    best_score = max(attempt.score for attempt in quiz_attempts) if total_attempts > 0 else 0
    passing_score = 40
    passed_attempts = sum(1 for attempt in quiz_attempts if attempt.score >= passing_score)
    pass_rate = (passed_attempts / total_attempts * 100) if total_attempts > 0 else 0
    
    # Calculate avg time taken
    total_seconds = 0
    counted_attempts = 0
    for attempt in quiz_attempts:
        if attempt.start_time and attempt.date_attempted:
            duration = (attempt.date_attempted - attempt.start_time).total_seconds()
            total_seconds += duration
            counted_attempts += 1
    avg_time_seconds = total_seconds / counted_attempts if counted_attempts > 0 else 0
    avg_time = {
        'hours': int(avg_time_seconds // 3600),
        'minutes': int((avg_time_seconds % 3600) // 60),
        'seconds': int(avg_time_seconds % 60)
    }
    
    # Calculate subject-wise performance
    for subject in subjects:
        subject_attempts = []
        for attempt in quiz_attempts:
            if attempt.quiz.chapter.subject_id == subject.id:
                subject_attempts.append(attempt)
        
        if subject_attempts:
            avg_score = sum(attempt.score for attempt in subject_attempts) / len(subject_attempts)
            subject_performance[subject.name] = {
                'average_score': round(avg_score, 1),
                'attempts': len(subject_attempts)
            }
    
    return render_template('admin/user_performance.html', 
                          user=user, 
                          quiz_attempts=quiz_attempts, 
                          subject_performance=subject_performance,
                          avg_score=average_score,
                          best_score=best_score,
                          total_attempts=total_attempts,
                          pass_rate=pass_rate,
                          avg_time=avg_time)

@app.route('/admin/quizzes')
@login_required
@admin_required
def manage_quizzes():
    quizzes = Quiz.query.all()
    chapters = Chapter.query.all()
    return render_template('admin/manage_quizzes.html', quizzes=quizzes, chapters=chapters)

@app.route('/admin/quizzes/add', methods=['POST'])
@login_required
@admin_required
def add_quiz():
    title = request.form.get('title')
    chapter_id = request.form.get('chapter_id')
    date_of_quiz = request.form.get('date_of_quiz')
    duration = request.form.get('duration')

    if not all([title, chapter_id, date_of_quiz, duration]):
        flash('All fields are required!', 'error')
        return redirect(url_for('manage_quizzes'))

    try:
        quiz = Quiz(
            title=title,
            chapter_id=chapter_id,
            date_of_quiz=datetime.strptime(date_of_quiz, '%Y-%m-%dT%H:%M'),
            duration=int(duration)
        )
        db.session.add(quiz)
        db.session.commit()
        flash('Quiz added successfully!', 'success')
        
        # Add success log
        print(f"Quiz '{title}' added successfully with ID {quiz.id}")
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding quiz: {str(e)}', 'error')
        print(f"Database error adding quiz: {str(e)}")

    return redirect(url_for('manage_quizzes'))

@app.route('/admin/quizzes/edit', methods=['POST'])
@login_required
@admin_required
def edit_quiz():
    quiz_id = request.form.get('quiz_id')
    title = request.form.get('title')
    chapter_id = request.form.get('chapter_id')
    date_of_quiz = request.form.get('date_of_quiz')
    duration = request.form.get('duration')

    if not all([quiz_id, title, chapter_id, date_of_quiz, duration]):
        flash('All fields are required!', 'error')
        return redirect(url_for('manage_quizzes'))

    try:
        quiz = Quiz.query.get_or_404(quiz_id)
        quiz.title = title
        quiz.chapter_id = chapter_id
        quiz.date_of_quiz = datetime.strptime(date_of_quiz, '%Y-%m-%dT%H:%M')
        quiz.duration = int(duration)
        db.session.commit()
        flash('Quiz updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating quiz: ' + str(e), 'error')

    return redirect(url_for('manage_quizzes'))

@app.route('/api/quizzes/<int:quiz_id>')
@login_required
@admin_required
def get_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    return render_template('admin/api/quiz_data.html', quiz=quiz)

@app.route('/api/quizzes/<int:quiz_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    
    # Check if there are any attempts for this quiz
    if quiz.attempts:
        return jsonify({'error': 'Cannot delete quiz with existing attempts'}), 400
    
    try:
        db.session.delete(quiz)
        db.session.commit()
        return jsonify({'message': 'Quiz deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/chapters/<int:chapter_id>/quizzes')
@login_required
@admin_required
def manage_chapter_quizzes(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    quizzes = Quiz.query.filter_by(chapter_id=chapter_id).all()
    return render_template('admin/manage_chapter_quizzes.html', chapter=chapter, quizzes=quizzes)

@app.route('/admin/quizzes/<int:quiz_id>/questions')
@login_required
@admin_required
def manage_quiz_questions(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    return render_template('admin/manage_quiz_questions.html', quiz=quiz, questions=questions)

@app.route('/admin/quizzes/<int:quiz_id>/questions/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_quiz_question(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    if request.method == 'POST':
        question_text = request.form.get('question_text')
        option1 = request.form.get('option1')
        option2 = request.form.get('option2')
        option3 = request.form.get('option3')
        option4 = request.form.get('option4')
        correct_option = request.form.get('correct_option')
        score = request.form.get('score')

        if not all([question_text, option1, option2, option3, option4, correct_option, score]):
            flash('All fields are required.', 'error')
            return redirect(url_for('add_quiz_question', quiz_id=quiz_id))

        try:
            question = Question(
                quiz_id=quiz_id,
                question_text=question_text,
                option1=option1,
                option2=option2,
                option3=option3,
                option4=option4,
                correct_option=int(correct_option),
                score=int(score)
            )
            db.session.add(question)
            db.session.commit()
            flash('Question added successfully!', 'success')
            return redirect(url_for('manage_quiz_questions', quiz_id=quiz_id))
        except Exception as e:
            db.session.rollback()
            flash('Error adding question. Please try again.', 'error')
            return redirect(url_for('add_quiz_question', quiz_id=quiz_id))

    return render_template('admin/add_quiz_question.html', quiz=quiz)

@app.route('/admin/quizzes/<int:quiz_id>/questions/<int:question_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_quiz_question(quiz_id, question_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    question = Question.query.get_or_404(question_id)
    
    if question.quiz_id != quiz_id:
        flash('Invalid question.', 'error')
        return redirect(url_for('manage_quiz_questions', quiz_id=quiz_id))

    if request.method == 'POST':
        question_text = request.form.get('question_text')
        option1 = request.form.get('option1')
        option2 = request.form.get('option2')
        option3 = request.form.get('option3')
        option4 = request.form.get('option4')
        correct_option = request.form.get('correct_option')
        score = request.form.get('score')

        if not all([question_text, option1, option2, option3, option4, correct_option, score]):
            flash('All fields are required.', 'error')
            return redirect(url_for('edit_quiz_question', quiz_id=quiz_id, question_id=question_id))

        try:
            question.question_text = question_text
            question.option1 = option1
            question.option2 = option2
            question.option3 = option3
            question.option4 = option4
            question.correct_option = int(correct_option)
            question.score = int(score)
            db.session.commit()
            flash('Question updated successfully!', 'success')
            return redirect(url_for('manage_quiz_questions', quiz_id=quiz_id))
        except Exception as e:
            db.session.rollback()
            flash('Error updating question. Please try again.', 'error')
            return redirect(url_for('edit_quiz_question', quiz_id=quiz_id, question_id=question_id))

    return render_template('admin/edit_quiz_question.html', quiz=quiz, question=question)

@app.route('/admin/quizzes/<int:quiz_id>/questions/<int:question_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_quiz_question(quiz_id, question_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    question = Question.query.get_or_404(question_id)
    
    if question.quiz_id != quiz_id:
        return jsonify({'error': 'Invalid question.'}), 400

    try:
        db.session.delete(question)
        db.session.commit()
        return jsonify({'message': 'Question deleted successfully.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Error deleting question.'}), 500

@app.route('/api/questions/<int:question_id>')
@login_required
@admin_required
def get_question_data(question_id):
    question = Question.query.get_or_404(question_id)
    return render_template('admin/api/question_data.html', question=question)

if __name__ == '__main__':
    init_db()
    app.run(debug=True) 