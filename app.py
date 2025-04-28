from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from geminiapi import executor, analyzer
import markdown



chat_sessions = {}
error_detector_model = analyzer()
executor_model = executor()


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

@app.before_request
def require_login():
    allowed_routes = ['login', 'signup', 'forgot_password', 'update_password', 'static']
    if not current_user.is_authenticated and request.endpoint not in allowed_routes:
        return redirect(url_for('login'))

# Home Route
@app.route('/')
def home():
    return render_template('index.html')

# About Route
@app.route('/about')
def about():
    return render_template('about.html')

# Features Route
@app.route('/features')
def features():
    return render_template('features.html')

# Faqs Route
@app.route('/faqs') 
def faqs():
    return render_template('faqs.html')

# Executor Route
@app.route('/executor')
def executor():
    return render_template('executor.html')


@app.route("/analyze", methods=["POST"])
def analyze_code():
    code = request.json.get("code", "")
    session_id = request.json.get("session_id", "default")

    if not code.strip():
        return jsonify({"error": "Please enter code for analysis."})

    try:
        # Create or get chat session
        if session_id not in chat_sessions:
            chat_sessions[session_id] = {
                "error_detector": error_detector_model.start_chat(),
                "executor": executor_model.start_chat(),
            }

        # Send message to error detector
        response = chat_sessions[session_id]["error_detector"].send_message(code)

        # Convert markdown to HTML with extensions
        html_response = markdown.markdown(
            response.text,
            extensions=[
                "fenced_code",  # For code blocks
                "tables",  # For tables
                "nl2br",  # For converting newlines to line breaks
                "sane_lists",  # For cleaner lists
            ],
        )

        return jsonify({"text": response.text, "html": html_response})
    except Exception as e:
        return jsonify({"error": f"Error during analysis: {str(e)}"})


@app.route("/execute", methods=["POST"])
def execute_code():
    code = request.json.get("code", "")
    session_id = request.json.get("session_id", "default")

    if not code.strip():
        return jsonify({"error": "Please enter code for execution."})

    try:
        # Create or get chat session
        if session_id not in chat_sessions:
            chat_sessions[session_id] = {
                "error_detector": error_detector_model.start_chat(),
                "executor": executor_model.start_chat(),
            }

        # Send message to executor
        response = chat_sessions[session_id]["executor"].send_message(code)

        # Convert markdown to HTML with extensions
        html_response = markdown.markdown(
            response.text,
            extensions=[
                "fenced_code",  # For code blocks
                "tables",  # For tables
                "nl2br",  # For converting newlines to line breaks
                "sane_lists",  # For cleaner lists
            ],
        )

        return jsonify({"text": response.text, "html": html_response})
    except Exception as e:
        return jsonify({"error": f"Error during execution: {str(e)}"})


@app.route("/clear", methods=["POST"])
def clear_history():
    session_id = request.json.get("session_id", "default")

    # Reset the chat sessions
    if session_id in chat_sessions:
        chat_sessions[session_id] = {
            "error_detector": error_detector_model.start_chat(),
            "executor": executor_model.start_chat(),
        }

    return jsonify({"message": "History cleared successfully"})


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

        # Log in the user immediately after signup
        login_user(new_user)
        flash('Account created successfully! You are now logged in.', 'success')
        return redirect(url_for('home'))

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
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'danger')
    
    return render_template('login.html')

def login():
    if 'user' in session:
        flash('Please log out first', 'warning')
        return redirect(url_for('index'))
    return render_template('login.html')

# Forgot Password Route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    email_provided = None

    if request.method == 'POST':
        if 'confirmed_email' in request.form:
            # Handle password reset
            email = request.form.get('confirmed_email')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            if not email:
                flash('Email is missing. Please try again.', 'danger')
                return render_template('forgot_password.html', email_provided=None)

            if not new_password or not confirm_password:
                flash('Please fill out all password fields.', 'danger')
                return render_template('forgot_password.html', email_provided=email)

            if new_password != confirm_password:
                flash('Passwords do not match!', 'danger')
                return render_template('forgot_password.html', email_provided=email)

            user = User.query.filter_by(email=email).first()
            if user:
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                user.password = hashed_password
                db.session.commit()
                flash('Password has been reset successfully!', 'success')
                return redirect(url_for('login'))
            else:
                flash('User not found!', 'danger')
                return render_template('forgot_password.html', email_provided=None)

        elif 'email' in request.form:
            # Handle email verification
            email = request.form.get('email')

            if not email:
                flash('Please provide an email address.', 'danger')
                return render_template('forgot_password.html', email_provided=None)

            user = User.query.filter_by(email=email).first()

            if not user:
                flash('Email not found in our system.', 'danger')
                return render_template('forgot_password.html', email_provided=None)

            email_provided = email
            flash('Email verified. Set new password.', 'success')

    return render_template('forgot_password.html', email_provided=email_provided)

@app.route('/update_password', methods=['POST'])
def update_password():
    email = request.form.get('confirmed_email', None)
    new_password = request.form.get('new_password', None)
    confirm_password = request.form.get('confirm_password', None)

    if not email:
        flash('Email is missing. Please try again.', 'danger')
        return redirect(url_for('forgot_password'))

    if not new_password or not confirm_password:
        flash('Please fill out all password fields.', 'danger')
        return redirect(url_for('forgot_password', email_provided=email))

    if new_password != confirm_password:
        flash('Passwords do not match!', 'danger')
        return redirect(url_for('forgot_password', email_provided=email))

    user = User.query.filter_by(email=email).first()
    if user:
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Password has been reset successfully!', 'success')
        return redirect(url_for('login'))
    else:
        flash('User not found!', 'danger')
        return redirect(url_for('forgot_password'))

# Logout Route
@app.route('/logout')
def logout():
    # Clear user session
    session.clear()
    # If using Flask-Login
    # logout_user()
    flash('You have been successfully logged out', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)

