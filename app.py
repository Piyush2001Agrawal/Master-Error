from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
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
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'danger')
    
    return render_template('login.html')

# Forgot Password Route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Password reset instructions have been sent to your email.', 'info')
        else:
            flash('No account found with that email.', 'danger')
    return render_template('forgot_password.html')

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
    
