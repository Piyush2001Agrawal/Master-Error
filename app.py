from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
app = Flask(__name__)
app.secret_key = 'supersecretmre'

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)
    
    def __init__(self, username, email, password, user_type):
        self.username = username
        self.email = email
        self.password = password
        self.user_type = user_type
    
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Home Route
@app.route('/')
def home():
    flash('Welcome to the Flask App', 'info')
    return render_template('index.html')

# About Route
@app.route('/about')
def about():
    return render_template('about.html')

# Form Route
@app.route('/form', methods=['GET', 'POST'])
def forminput():
    return render_template('form.html')

# Results Route
@app.route('/results', methods=['GET', 'POST'])
def result():
    return render_template('results.html')

# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user_type = request.form['user_type']

        # Check if user exists
        existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
        if existing_user:
            flash('User already exists. Please log in.', 'danger')
            return redirect(url_for('login'))

        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password, user_type=user_type)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email_or_username = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email_or_username).first() or User.query.filter_by(username=email_or_username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    
    return render_template('login.html')

# Dashboard Route
@app.route('/dashboard')
@login_required
def dashboard():
    return f'Welcome, {current_user.username}! You are logged in as a {current_user.user_type}.'

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

# Initialize Database

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
