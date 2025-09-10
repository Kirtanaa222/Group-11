from flask import Flask, render_template, request, redirect, url_for, session, abort
from flask_sqlalchemy import SQLAlchemy 
from werkzeug.security import generate_password_hash, check_password_hash 
from werkzeug.utils import secure_filename
import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' 
from datetime import datetime, timedelta
from flask import abort
from flask_mail import Mail, Message
import requests

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sql.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "supersecret"
db = SQLAlchemy(app)

UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# new database because needed for admin functionality
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    faculty = db.Column(db.String(50), nullable=False)
    student_id = db.Column(db.String(50), unique=True, nullable=False)
    user_email = db.Column(db.String(50), unique=True, nullable=False)
    mmu_email = db.Column(db.String(50), unique=True, nullable=True)
    bio = db.Column(db.Text, nullable=True)
    avatar = db.Column(db.String(200), nullable=True)
    background = db.Column(db.String(200), nullable=True)
    verified = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    admin = db.Column(db.Boolean, default=False) 
    mmu_email_updated_at = db.Column(db.DateTime, nullable=True)

with app.app_context():
    db.create_all()

#----------------------------------ADMIN-----------------------------------------
# Helper function to check if user is logged in or is admin
@app.route('/admin')
def admin_dashboard():
    if not is_logged_in_admin():
        abort(403)
    users = User.query.all()
    return render_template('admin.html', users=users)

def is_logged_in_admin():
    user_id = session.get("user_id")
    if not user_id:
        return False
    user = User.query.get(user_id)
    return user and user.admin

@app.route('/admin/users/<int:user_id>/ban', methods=['POST'])
def admin_ban_user(user_id):
    if not is_logged_in_admin():
        abort(403)
    user = User.query.get_or_404(user_id)
    # Send reminder if MMU email is not set or invalid
    if not is_mmu_email(user.mmu_email):
        send_mmu_reminder_email(user)
    user.status = 'banned'
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

def send_mmu_reminder_email(user):
    msg = Message(
        subject="Reminder: Update Your MMU Email",
        sender=app.config['MAIL_USERNAME'],
        recipients=[user.user_email]
    )
    msg.body = f"""
    Hi {user.username},

    Please update your MMU email address in your profile as soon as possible.
    If you do not update it, your account will be banned forever.

    Regards,
    Admin Team
    """
    mail.send(msg)

@app.route('/admin/users/<int:user_id>/unban', methods=['POST'])
def admin_unban_user(user_id):
    if not is_logged_in_admin():
        abort(403)
    user = User.query.get_or_404(user_id)
    user.status = 'active'
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

# Email config (use your own SMTP settings)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'kdkirtu@gmail.com'
app.config['MAIL_PASSWORD'] = 'quzv jfzf gsgt ntix'
mail = Mail(app)

def send_verification_email(user):
    msg = Message(
        subject="Your Account Has Been Verified",
        sender=app.config['MAIL_USERNAME'],
        recipients=[user.user_email]
    )
    msg.body = f"""
    Hi {user.username},

    Congratulations! Your account has been verified because you updated your MMU email within the required time.

    You now have full access to the platform.

    Regards,
    Admin Team
    """
    mail.send(msg)

#------------------------------------USER----------------------------------------
@app.route("/")
def home():
    return render_template("home.html", username=session.get("username"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        student_id = request.form["student_id"]
        user_email = request.form["user_email"]
        faculty = request.form.get("faculty")  

        # to check if the user exists in db
        if User.query.filter_by(username=username).first():
            return render_template("signup.html", error="Username already exists. Please try again.")

        if User.query.filter_by(student_id=student_id).first():
            return render_template("signup.html", error="Student ID already exists. Please check.")
        
        if User.query.filter_by(user_email=user_email).first():
            return render_template("signup.html", error="Email already exists.")

        hashed_pw = generate_password_hash(password, method="scrypt")
        new_user = User(username=username, password=hashed_pw, faculty=faculty, student_id=student_id, user_email=user_email)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user_input = request.form["user_input"]
        password = request.form["password"]

        user = User.query.filter(
            (User.username == user_input) | (User.user_email == user_input)
        ).first()
        
        if user and check_password_hash(user.password, password):
            if user.status == 'banned':
                # Redirect banned users to unlock account page
                return redirect(url_for("unlock_account"))
            session["user_id"] = user.id
            session["username"] = user.username
            session["is_admin"] = user.admin
            return redirect(url_for("profile"))
        else:
            return render_template("login.html", error="Invalid username or password.")
    return render_template("login.html")

#------------------------------unlock_account---------------------------------
@app.route("/unlock_acc", methods=["GET", "POST"])
def unlock_account():
    error = None
    success = None
    if request.method == "POST":
        username = request.form.get("username")
        student_id = request.form.get("student_id")
        mmu_email = request.form.get("mmu_email")

        user = User.query.filter_by(username=username, student_id=student_id).first()
        if not user or user.status != 'banned':
            error = "Account not found or not banned."
        elif User.query.filter_by(mmu_email=mmu_email).first() and user.mmu_email != mmu_email:
            error = "MMU email already exists. Please use a different MMU email."
        elif not is_mmu_email(mmu_email):
            error = "Please enter a valid MMU email (@mmu.edu.my OR @student.mmu.edu.my)."
        else:
            user.mmu_email = mmu_email
            user.mmu_email_updated_at = datetime.utcnow()
            user.verified = True
            user.status = 'active'
            db.session.commit()
            send_verification_email(user)
            # Redirect to login page with success message
            return redirect(url_for("login", success="Your account has been updated and unbanned. You can now log in."))
    return render_template("unlock_acc.html", error=error, success=success)

#----------------------profile----------------------------
def is_mmu_email(email):
    if not email:
        return False
    return email.endswith("@mmu.edu.my") or email.endswith("@student.mmu.edu.my")

@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    if user.status == 'banned':
        return redirect(url_for("unlock_account")) # Redirect banned users to unlock page
    
    avatar = user.avatar or "default_avatar.png"
    background = user.background or "default_bg.jpg"
    bio = user.bio or ""

    #check if user update mmu email
    mmu_reminder = None
    if not is_mmu_email(user.mmu_email):
        mmu_reminder = "You haven't updated your MMU email yet. Click below to update."

    #send data to profile.html to display the profile page
    return render_template("profile.html",
                           username=user.username,
                           avatar=avatar,
                           background=background,
                           bio=bio,
                           mmu_reminder=mmu_reminder)

#------------------------------display_profile-----------------------------

@app.route("/display_profile/<int:user_id>")
def display_profile(user_id):
    user = User.query.get(user_id)
    if not user:
        return "User not found", 404

    avatar = user.avatar or "default_avatar.png"
    background = user.background or "default_bg.jpg"
    bio = user.bio or ""

    return render_template("display_profile.html",
                           user=user,
                           avatar=avatar,
                           background=background,
                           bio=bio)


#------------------------------edit_profile---------------------------------

@app.route("/edit_profile/<int:user_id>", methods=["GET", "POST"])
def edit_profile(user_id):
    user = User.query.get(user_id)
    if not user:
        return "User not found", 404

    avatar = user.avatar or "default_avatar.png"
    background = user.background or "default_bg.jpg"
    bio = user.bio or ""
    error = None

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["user_id"] != user_id and not session.get("is_admin"):
        abort(403)

    user = User.query.get(user_id)
    if not user:
        abort(404)


    if is_mmu_email(user.mmu_email): #false means that email cannot be edited)
        email_editable = False
    else:
        email_editable = True
    # email_editable = not is_mmu_email(user.mmu_email)
    # true when email is mmuemail, 'not' make it become false(means that email cannot be edited)

    if request.method == "POST":
        form_name = request.form.get("form_name")

        if form_name == "bio":
            bio_text = request.form.get("bio", "")
            user.bio = bio_text

        elif form_name == "avatar":
            avatar_file = request.files.get("avatar")
            if avatar_file and allowed_file(avatar_file.filename):
                filename = secure_filename(avatar_file.filename)
                path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                avatar_file.save(path)
                user.avatar = f"/static/uploads/{filename}"

        elif form_name == "background":
            bg_file = request.files.get("background")
            if bg_file and allowed_file(bg_file.filename):
                filename = secure_filename(bg_file.filename)
                path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                bg_file.save(path)
                user.background = f"/static/uploads/{filename}"

        elif form_name == "mmu_email":
            new_mmu_email = request.form.get("mmu_email")
            if new_mmu_email and email_editable:
                existing_user = User.query.filter_by(mmu_email=new_mmu_email).first()
                if existing_user and existing_user.id != user.id:
                    error = "MMU email already exists. Please use a different MMU email."
                elif is_mmu_email(new_mmu_email):
                    user.mmu_email = new_mmu_email
                    user.mmu_email_updated_at = datetime.utcnow()

                    # Check if updated within 7 days of signup
                    if (user.mmu_email_updated_at - user.created_at) <= timedelta(days=7):
                        user.verified = True
                        user.status = 'active'  # Unban the user
                        send_verification_email(user)

                    email_editable = False
                else:
                    error = "Please enter a valid MMU email (@mmu.edu.my or @student.mmu.edu.my)."
        db.session.commit()

    return render_template("edit_profile.html",
                           user=user,
                           avatar=avatar,
                           background=background,
                           bio=bio,
                           error=error,
                           email_editable=email_editable)

@app.route("/search_users")
def search_users():
    faculty = request.args.get("faculty")
    if faculty:
        users = User.query.filter_by(faculty=faculty).all()
    else:
        users = User.query.all()
    return render_template("search.html", users=users, faculty=faculty)


#------------------------------chat---------------------------------
NAKAMA_HOST = "http://127.0.0.1:7350"
NAKAMA_SERVER_KEY = "defaultkey"

def nakama_authenticate(email, password):
    url = f"{NAKAMA_HOST}/v2/account/authenticate/email?create=true"
    payload = {"email": email, "password": password}
    headers = {"Authorization": f"Bearer {NAKAMA_SERVER_KEY}"}
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 200:
        return response.json().get("token")
    return None

@app.route('/chatroom', methods=['GET', 'POST'])
def chat():
    if "user_id" not in session:
        return redirect(url_for("login"))
    user = User.query.get(session["user_id"])
    nakama_token = nakama_authenticate(user.user_email, user.password)
    messages = []
    if nakama_token:
        # Example: send message (pseudo-code, replace with actual Nakama API)
        if request.method == "POST":
            message_text = request.form["message"]
            # Here you would send the message to Nakama using REST API
            # Example endpoint: /v2/chat/send (not actual, see Nakama docs)
        # Example: get messages (pseudo-code, replace with actual Nakama API)
        # You would fetch messages from Nakama using REST API
        # For demo, use static messages
        messages = [
            {"username": user.username, "content": "Welcome to the chatroom!"}
        ]
    return render_template("chatroom.html", messages=messages)
    

#--------------logout------------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# Run the app
if __name__ == "__main__":
    app.run(debug=True)