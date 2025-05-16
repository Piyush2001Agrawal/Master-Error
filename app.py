from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from geminiapi import executor, analyzer
import markdown
import os
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from authlib.integrations.flask_client import OAuth
from urllib.parse import urlencode
import secrets
from flask_mail import Mail, Message
import random
import string

# Load environment variables
load_dotenv()

# Store OTPs with expiration time
otp_store = {}

chat_sessions = {}
error_detector_model = analyzer()
executor_model = executor()


app = Flask(__name__)
app.secret_key = 'supersecretmre'

# OAuth Configuration
oauth = OAuth(app)

# Google OAuth
if not os.getenv('GOOGLE_CLIENT_ID') or not os.getenv('GOOGLE_CLIENT_SECRET'):
    print("Warning: Google OAuth credentials not set. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env file")

# Define the redirect URI explicitly
GOOGLE_REDIRECT_URI = 'http://127.0.0.1:5000/login/google/authorize'

google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
    access_token_url='https://oauth2.googleapis.com/token',
    api_base_url='https://www.googleapis.com/oauth2/v3/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={
        'scope': 'openid email profile',
        'prompt': 'consent',
        'response_type': 'code',
        'token_endpoint_auth_method': 'client_secret_basic',
        'redirect_uri': GOOGLE_REDIRECT_URI
    }
)



# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
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
    profile_picture = db.Column(db.String(255), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    location = db.Column(db.String(100), nullable=True)
    skills = db.Column(db.String(255), nullable=True)
    interests = db.Column(db.String(255), nullable=True)
    posts = db.Column(db.Integer, default=0)
    solutions = db.Column(db.Integer, default=0)
    reputation = db.Column(db.Integer, default=0)
    github_url = db.Column(db.String(255), nullable=True)
    linkedin_url = db.Column(db.String(255), nullable=True)
    twitter_url = db.Column(db.String(255), nullable=True)
    website_url = db.Column(db.String(255), nullable=True)
    
    def __init__(self, username, email, password, user_type):
        self.username = username
        self.email = email
        self.password = password
        self.user_type = user_type

# Create database tables
with app.app_context():
    # db.drop_all()  # Drop all existing tables - Commented out to preserve user data
    db.create_all()  # Create new tables with updated schema

# Email Configuration
mail = Mail(app)

# Password Reset Tokens
password_reset_tokens = {}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def require_login():
    allowed_routes = [
        'login', 'signup', 'forgot_password', 'update_password', 'static',
        'google_login', 'google_authorize', 'facebook_login', 'facebook_authorize'
    ]
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
    user_input = request.json.get("user_input", "")
    is_input_response = request.json.get("is_input_response", False)

    if not code.strip() and not is_input_response:
        return jsonify({"error": "Please enter code for execution."})

    try:
        # Create or get chat session
        if session_id not in chat_sessions:
            chat_sessions[session_id] = {
                "error_detector": error_detector_model.start_chat(),
                "executor": executor_model.start_chat(),
            }

        # If this is the first request (not an input response)
        if not is_input_response:
            response = chat_sessions[session_id]["executor"].send_message(code)
        else:
            formatted_input = f"User provided input: {user_input}"
            response = chat_sessions[session_id]["executor"].send_message(formatted_input)

        # Convert markdown to HTML
        html_response = markdown.markdown(
            response.text,
            extensions=[
                "fenced_code",
                "tables", 
                "nl2br",
                "sane_lists",
            ],
        )

        requires_input = "USER_INPUT_REQUIRED:" in response.text
        
        return jsonify({
            "text": response.text, 
            "html": html_response,
            "requires_input": requires_input
        })
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
        
        # Validate required fields
        if not all([username, email, password, user_type]):
            flash('All fields are required', 'danger')
            return redirect(url_for('signup'))

        # Password validation
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
            return redirect(url_for('signup'))
        if not any(char.isdigit() for char in password):
            flash('Password must contain at least one digit', 'danger')
            return redirect(url_for('signup'))
        if not any(char.isalpha() for char in password):
            flash('Password must contain at least one letter', 'danger')
            return redirect(url_for('signup'))
        if not any(char in '!@#$%^&*()_+' for char in password):
            flash('Password must contain at least one special character', 'danger')
            return redirect(url_for('signup'))
        if not any(char.isupper() for char in password):
            flash('Password must contain at least one uppercase letter', 'danger')
            return redirect(url_for('signup'))

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

# Helper functions for OTP
def generate_otp():
    """Generate a 6-digit OTP"""
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(email, otp):
    """Send OTP via email"""
    body = f"""
    Your OTP for password reset is: {otp}
    This OTP is valid for 10 minutes.
    
    If you did not request this, please ignore this email.
    
    Regards,
    MasterError Team
    """
    try:
        msg = Message(
            'Password Reset OTP - MasterError',
            recipients=[email],
            body=body
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def store_otp(email, otp):
    """Store OTP with 10-minute expiration"""
    expiration = datetime.now() + timedelta(minutes=10)
    otp_store[email] = {'otp': otp, 'expiration': expiration}

def verify_otp(email, otp):
    """Verify OTP and check if it's not expired"""
    if email not in otp_store:
        return False
    stored = otp_store[email]
    if datetime.now() > stored['expiration']:
        del otp_store[email]
        return False
    is_valid = stored['otp'] == otp
    if is_valid:
        del otp_store[email]
    return is_valid

# Forgot Password Route
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        otp = request.form.get('otp')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('No account found with that email address.', 'danger')
            return render_template('forgot_password.html')

        # Step 1: User enters email and requests OTP
        if not otp and not new_password:
            # Generate and send OTP
            new_otp = generate_otp()
            if send_otp_email(email, new_otp):
                store_otp(email, new_otp)
                flash('OTP has been sent to your email. Please check your inbox.', 'success')
                return render_template('forgot_password.html', email_provided=email, show_otp=True)
            else:
                flash('Error sending OTP. Please try again.', 'danger')
                return render_template('forgot_password.html')
        
        # Step 2: User enters OTP
        elif otp and not new_password:
            if verify_otp(email, otp):
                flash('OTP verified. Please enter your new password.', 'success')
                return render_template('forgot_password.html', email_provided=email, otp_verified=True)
            else:
                flash('Invalid or expired OTP. Please try again.', 'danger')
                return render_template('forgot_password.html', email_provided=email, show_otp=True)
        
        # Step 3: User enters new password
        elif new_password and confirm_password:
            if new_password != confirm_password:
                flash('Passwords do not match.', 'danger')
                return render_template('forgot_password.html', email_provided=email, otp_verified=True)
            
            # Update password
            user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            db.session.commit()
            flash('Your password has been updated! You can now log in.', 'success')
            return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

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

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    username = request.form.get('username')
    email = request.form.get('email')
    bio = request.form.get('bio')
    location = request.form.get('location')
    skills = request.form.get('skills')
    interests = request.form.get('interests')
    profile_picture = request.files.get('profile_picture')

    if not username or not email:
        flash('Username and email are required.', 'danger')
        return redirect(url_for('profile'))

    try:
        # Update user details
        current_user.username = username
        current_user.email = email
        current_user.bio = bio
        current_user.location = location
        current_user.skills = skills
        current_user.interests = interests

        # Handle profile picture upload
        if profile_picture:
            # Generate unique filename
            filename = secure_filename(profile_picture.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{filename}"
            
            # Save the file
            picture_path = os.path.join('static/images', filename)
            profile_picture.save(picture_path)
            current_user.profile_picture = filename

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    except Exception as e:
        print(f"Error updating profile: {e}")
        flash('An error occurred while updating your profile.', 'danger')
        return redirect(url_for('profile'))

@app.route('/login/google')
def google_login():
    if not os.getenv('GOOGLE_CLIENT_ID') or not os.getenv('GOOGLE_CLIENT_SECRET'):
        flash('Google login is not configured. Please check your configuration.', 'danger')
        return redirect(url_for('login'))

    # Store the next URL if provided
    next_url = request.args.get('next')
    if next_url:
        session['next_url'] = next_url

    # Generate a random state
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    
    try:
        return google.authorize_redirect(redirect_uri=GOOGLE_REDIRECT_URI, state=state)
    except Exception as e:
        print(f"Google login error: {str(e)}")
        flash('An error occurred during Google login. Please try again.', 'danger')
        return redirect(url_for('login'))

@app.route('/login/google/authorize')
def google_authorize():
    try:
        # Verify state
        state = session.pop('oauth_state', None)
        if not state or state != request.args.get('state'):
            flash('Invalid state parameter. Please try again.', 'danger')
            return redirect(url_for('login'))

        token = google.authorize_access_token()
        if not token:
            flash('Failed to get token from Google', 'danger')
            return redirect(url_for('login'))
            
        # Get user info using the userinfo endpoint
        resp = google.get('userinfo', token=token)
        if resp.status_code != 200:
            flash('Failed to get user info from Google', 'danger')
            return redirect(url_for('login'))
            
        user_info = resp.json()
        
        if not user_info.get('email'):
            flash('Failed to get email from Google', 'danger')
            return redirect(url_for('login'))
        
        # Check if user exists
        user = User.query.filter_by(email=user_info['email']).first()
        
        if not user:
            # Create new user
            username = user_info.get('name', '').replace(' ', '_').lower()
            # Ensure username is unique
            base_username = username
            counter = 1
            while User.query.filter_by(username=username).first():
                username = f"{base_username}_{counter}"
                counter += 1
                
            user = User(
                username=username,
                email=user_info['email'],
                password=bcrypt.generate_password_hash(os.urandom(24)).decode('utf-8'),
                user_type='beginner'
            )
            db.session.add(user)
            db.session.commit()
        
        login_user(user)
        flash('Successfully logged in with Google!', 'success')
        
        # Redirect to next_url if it exists
        next_url = session.pop('next_url', None)
        return redirect(next_url or url_for('profile'))
        
    except Exception as e:
        print(f"Google login error: {str(e)}")
        flash('An error occurred during Google login. Please try again.', 'danger')
        return redirect(url_for('login'))

@app.route('/login/facebook')
def facebook_login():
    redirect_uri = url_for('facebook_authorize', _external=True)
    return facebook.authorize_redirect(redirect_uri)

@app.route('/login/facebook/authorize')
def facebook_authorize():
    token = facebook.authorize_access_token()
    resp = facebook.get('me?fields=id,name,email')
    user_info = resp.json()
    
    # Check if user exists
    user = User.query.filter_by(email=user_info['email']).first()
    
    if not user:
        # Create new user
        user = User(
            username=user_info['name'],
            email=user_info['email'],
            password=bcrypt.generate_password_hash(os.urandom(24)).decode('utf-8'),
            user_type='beginner'
        )
        db.session.add(user)
        db.session.commit()
    
    login_user(user)
    flash('Successfully logged in with Facebook!', 'success')
    return redirect(url_for('profile'))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)

