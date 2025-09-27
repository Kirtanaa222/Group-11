import eventlet
eventlet.monkey_patch()
from flask import Flask, render_template, request, redirect, url_for, session, abort
from flask_sqlalchemy import SQLAlchemy 
from werkzeug.security import generate_password_hash, check_password_hash 
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' 
from datetime import datetime, timedelta
from flask import abort
from flask_socketio import SocketIO, emit, join_room
import resend

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///sql.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "supersecret"
serializer = URLSafeTimedSerializer(app.secret_key)
RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
db = SQLAlchemy(app)
socketio = SocketIO(app)

UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

class User(db.Model):
    #signupp
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)
    faculty = db.Column(db.String(100), nullable=False)
    student_id = db.Column(db.String(100), unique=True, nullable=False)
    user_email = db.Column(db.String(100), unique=True, nullable=False)
    #edit profile
    mmu_email = db.Column(db.String(100), unique=True, nullable=True)
    bio = db.Column(db.Text, nullable=True)
    avatar = db.Column(db.String(300), nullable=True)
    background = db.Column(db.String(300), nullable=True)
    preferred_subjects = db.Column(db.String(100), nullable=True)
    #admin profile
    verified = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    admin = db.Column(db.Boolean, default=False) 
    mmu_email_updated_at = db.Column(db.DateTime, nullable=True)

#Message
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(100), nullable=False)
    recipient = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Timetable
class TimetableEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    day_of_week = db.Column(db.String(10), nullable=False)  # e.g., 'Monday'
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    date = db.Column(db.Date, nullable=True)  # <-- Add this line

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
    if not RESEND_API_KEY:
        print("Resend API key not set. Skipping email.")
        return
    resend.api_key = RESEND_API_KEY
    resend.Emails.send({
        "from": "noreply@studybae.com",
        "to": user.user_email,
        "subject": "Reminder: Update Your MMU Email",
        "text": f"""
Hi {user.username},

Please update your MMU email address in your profile as soon as possible.
If you do not update it, your account will be banned forever.

Regards,
Admin Team
"""
    })

@app.route('/admin/users/<int:user_id>/unban', methods=['POST'])
def admin_unban_user(user_id):
    if not is_logged_in_admin():
        abort(403)
    user = User.query.get_or_404(user_id)
    user.status = 'active'
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

def send_verification_email(user):
    if not RESEND_API_KEY:
        print("Resend API key not set. Skipping email.")
        return
    resend.api_key = RESEND_API_KEY
    resend.Emails.send({
        "from": "noreply@studybae.com",
        "to": user.user_email,
        "subject": "Your Account Has Been Verified",
        "text": f"""
Hi {user.username},

Congratulations! Your account has been verified because you updated your MMU email within the required time.

You now have full access to the platform.

Regards,
Admin Team
"""
    })

#---------------------------home----------------------------------
@app.route("/")
def home():
    return render_template("home.html", username=session.get("username"))

#---------------------------signup----------------------------------
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

        hashed_pw = generate_password_hash(password, method="scrypt") #encprt the password
        new_user = User(username=username, password=hashed_pw, faculty=faculty, student_id=student_id, user_email=user_email)
        db.session.add(new_user) #add to db
        db.session.commit()
        return redirect(url_for("login"))

    return render_template("signup.html")

#---------------------------login----------------------------------
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
            return redirect(url_for("study_space"))
        else:
            return render_template("login.html", error="Invalid username or password.")
    return render_template("login.html")

#---------------------------forgotpassword----------------------------------

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_pw():
    if request.method == "POST":
        email = request.form.get("email").strip().lower()
        user = User.query.filter_by(user_email=email).first()
        if user:
            token = serializer.dumps(email, salt="reset-salt")
            reset_url = url_for("reset_pw", token=token, _external=True)

            if RESEND_API_KEY:
                resend.api_key = RESEND_API_KEY
                resend.Emails.send({
                    "from": "noreply@studybae.com",
                    "to": email,
                    "subject": "Password Reset Request",
                    "text": f"""
Hi {user.username},

You requested to reset your password. Click the link below to reset it:
{reset_url}

This link will expire in 10 minutes.

If you did not request this, please ignore this email.
"""
                })
            else:
                print("Resend API key not set. Skipping email.")

            return render_template("forgot_pw.html", message="A reset link has been sent to your email.")
        else:
            return render_template("forgot_pw.html", error="Email not found.")
    return render_template("forgot_pw.html")

#-----------------------------resetpassword---------------------------------------
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_pw(token):
    try:
        email = serializer.loads(token, salt="reset-salt", max_age=600)  # valid for 10mins
    except Exception:
        return render_template("reset_pw.html", error="The reset link is invalid or has expired.")

    user = User.query.filter_by(user_email=email).first()
    if not user:
        return render_template("reset_pw.html", error="User not found.")

    if request.method == "POST":
        new_pwd = request.form.get("password")
        confirm = request.form.get("confirm")
        if new_pwd != confirm:
            return render_template("reset_pw.html", error="Passwords do not match.")

        user.password = generate_password_hash(new_pwd, method="scrypt")
        db.session.commit()
        return redirect(url_for("login"))

    return render_template("reset_pw.html")

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

#----------------------Study Space----------------------------
def is_mmu_email(email):
    if not email:
        return False
    return email.endswith("@mmu.edu.my") or email.endswith("@student.mmu.edu.my")

@app.route("/study_space", methods=["GET", "POST"])
def study_space():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    if user.status == 'banned':
        return redirect(url_for("unlock_account")) # Redirect banned users to unlock page
    
    avatar = user.avatar or "img/default_avatar.jpg"
    background = user.background or "default_bg.jpg"
    bio = user.bio or ""

# MMU email reminder with countdown
    mmu_reminder = None
    days_left = None
    if not is_mmu_email(user.mmu_email):
        delta = timedelta(days=7) - (datetime.utcnow() - user.created_at)
        days_left = max(delta.days, 0)
        mmu_reminder = "You haven't updated your MMU email yet. Click below to update."

    # Fetch user's timetable entries
    timetable_entries = TimetableEntry.query.filter_by(user_id=user.id).order_by(TimetableEntry.day_of_week, TimetableEntry.start_time).all()

    #send data to study_space.html to display the study space page
    return render_template("study_space.html",
                           username=user.username,
                           avatar=avatar,
                           background=background,
                           bio=bio,
                           mmu_reminder=mmu_reminder,
                           timetable_entries=timetable_entries,
                           days_left=days_left)

#------------------------------display_profile-----------------------------

@app.route("/display_profile/<int:user_id>")
def display_profile(user_id):
    if "user_id" not in session:
        # it redirects user to login
        return redirect(url_for("login", next=request.url))
    
    user = User.query.get(user_id)
    if not user:
        return "User not found", 404

    avatar = user.avatar or "img/default_avatar.jpg"
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

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session["user_id"] != user_id and not session.get("is_admin"):
        abort(403)

    avatar = user.avatar or "img/default_avatar.jpg"
    background = user.background or "default_bg.jpg"
    bio = user.bio or ""
    error = None

    # check if email is editable
    if is_mmu_email(user.mmu_email):
        email_editable = False #false means that email cannot be edited
    else:
        email_editable = True

    if request.method == "POST":
        form_name = request.form.get("form_name")

        if form_name == "avatar":
            file = request.files.get("avatar")
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(path)
                user.avatar = f"uploads/{filename}"
                db.session.commit()
            return redirect(url_for("edit_profile", user_id=user.id))

        if form_name == "all":
            bio_text = request.form.get("bio", "")
            user.bio = bio_text

            bg_file = request.files.get("background")
            if bg_file and allowed_file(bg_file.filename):
                filename = secure_filename(bg_file.filename)
                path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                bg_file.save(path)
                user.background = f"uploads/{filename}"

            selected_subjects = request.form.getlist("subjects")
            user.preferred_subjects = ",".join(selected_subjects)

            new_mmu_email = request.form.get("mmu_email") or request.form.get("mmu_email1")
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

            if not error:            
                db.session.commit()
                return redirect(url_for("display_profile", user_id=user.id))

    return render_template(
        "edit_profile.html",
        user=user,
        avatar=avatar,
        background=background,
        bio=user.bio,
        error=error,
        email_editable=email_editable
    )
#------------------------------search---------------------------------

@app.route("/search_users")
def search_users():
    faculty = request.args.get("faculty", "").strip()
    subject = request.args.get("subject", "").strip()

    query = User.query

    # Case-insensitive faculty match
    if faculty:
        query = query.filter(User.faculty.ilike(faculty))

    # Case-insensitive subject search (partial match)
    if subject:
        query = query.filter(User.preferred_subjects.ilike(f"%{subject}%"))

    users = query.all()
    return render_template(
        "search.html",
        users=users,
        faculty=faculty,
        subject=subject
    )



#------------------------------timetable---------------------------------
@app.route("/timetable", methods=["GET", "POST"])
def timetable():
    if "user_id" not in session:
        return redirect(url_for("login"))
    user_id = session["user_id"]
    error = None
    if request.method == "POST":
        date_str = request.form.get("date")
        day_of_week = request.form.get("day_of_week")
        start_time = request.form.get("start_time")
        end_time = request.form.get("end_time")
        subject = request.form.get("subject")
        description = request.form.get("description")
        try:
            entry = TimetableEntry(
                user_id=user_id,
                day_of_week=day_of_week,
                start_time=datetime.strptime(start_time, "%H:%M").time(),
                end_time=datetime.strptime(end_time, "%H:%M").time(),
                subject=subject,
                description=description,
                date=datetime.strptime(date_str, "%Y-%m-%d").date() if date_str else None
            )
            db.session.add(entry)
            db.session.commit()
        except Exception as e:
            error = "Invalid input or time format."

    entries = TimetableEntry.query.filter_by(user_id=user_id).order_by(TimetableEntry.day_of_week, TimetableEntry.start_time).all()
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    return render_template("timetable.html", entries=entries, days=days, error=error)

@app.route('/delete_timetable_entry/<int:entry_id>', methods=['POST'])
def delete_timetable_entry(entry_id):
    entry = TimetableEntry.query.get_or_404(entry_id)
    # Optionally, check if the current user owns this entry
    db.session.delete(entry)
    db.session.commit()
    return redirect(url_for('timetable'))

#------------------------------chat---------------------------------
@app.route("/message")
def message():
    username = session.get("username")
    recipient = request.args.get("recipient", "")
    messages = Message.query.filter(
        (Message.sender == username) | (Message.recipient == username)
    ).order_by(Message.timestamp).all()
    return render_template("message.html", username=username, messages=messages, recipient=recipient)

@socketio.on('join')
def on_join(data):
    username = data['username']
    join_room(username)

@socketio.on('send_message')
def handle_send_message(data):
    recipient = data['recipient']
    message = data['message']
    sender = session.get('username')
    # Save to database
    msg = Message(sender=sender, recipient=recipient, content=message)
    db.session.add(msg)
    db.session.commit()
    # Show to sender immediately
    emit('receive_message', {'sender': sender, 'message': message}, room=sender)
    # Deliver to recipient if online
    emit('receive_message', {'sender': sender, 'message': message}, room=recipient)


#--------------logout------------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# Run the app
if __name__ == "__main__":
    socketio.run(app, debug=True)