from flask import Flask, render_template, request, redirect, url_for, session, abort
from flask_sqlalchemy import SQLAlchemy 
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash 
from werkzeug.utils import secure_filename
import os 
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sql.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "supersecret"
serializer = URLSafeTimedSerializer(app.secret_key)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

class User(db.Model):
    #signupp
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    faculty = db.Column(db.String(50), nullable=False)
    student_id = db.Column(db.String(50), unique=True, nullable=False)
    user_email = db.Column(db.String(50), unique=True, nullable=False)
    #edit profile
    mmu_email = db.Column(db.String(50), unique=True, nullable=True)
    bio = db.Column(db.Text, nullable=True)
    avatar = db.Column(db.String(200), nullable=True)
    background = db.Column(db.String(200), nullable=True)
    preferred_subjects = db.Column(db.String(100), nullable=True)
    #admin profile
    is_verified = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False) 

with app.app_context():
    db.create_all()

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
    return user and user.is_admin

# Admin routes- only accessible to admin users. so need to sign up first then manually set is_admin to True in the database
@app.route('/admin/users/<int:user_id>/ban', methods=['POST'])
def admin_ban_user(user_id):
    if not is_logged_in_admin():
        abort(403)
    user = User.query.get_or_404(user_id)
    user.status = 'banned'
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/users/<int:user_id>/unban', methods=['POST'])
def admin_unban_user(user_id):
    if not is_logged_in_admin():
        abort(403)
    user = User.query.get_or_404(user_id)
    user.status = 'active'
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

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

        hashed_pw = generate_password_hash(password, method="scrypt")
        new_user = User(username=username, password=hashed_pw, faculty=faculty, student_id=student_id, user_email=user_email)
        db.session.add(new_user)
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
                return render_template("login.html", error="Your account has been banned.")
            session["user_id"] = user.id
            session["username"] = user.username
            session["is_admin"] = user.is_admin
            return redirect(url_for("profile"))
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
            return render_template("forgot_pw.html", message=f"Click the link to reset your password: {reset_url}")
        else:
            return render_template("forgot_pw.html", error="Email not found.")
    return render_template("forgot_pw.html")

#-----------------------------resetpassword---------------------------------------

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_pw(token):
    try:
        email = serializer.loads(token, salt="reset-salt", max_age=900)  # valid for 15 minutes
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
    if "user_id" not in session:
        # it redirects user to login
        return redirect(url_for("login", next=request.url))
    
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
                user.avatar = f"uploads/{filename}"

        elif form_name == "background":
            bg_file = request.files.get("background")
            if bg_file and allowed_file(bg_file.filename):
                filename = secure_filename(bg_file.filename)
                path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                bg_file.save(path)
                user.background = f"uploads/{filename}"

        elif form_name == "mmu_email":
            new_mmu_email = request.form.get("mmu_email")
            if new_mmu_email and email_editable:
                if is_mmu_email(new_mmu_email):
                    user.mmu_email = new_mmu_email
                    email_editable = False
                else:
                    error = "Please enter a valid MMU email (@mmu.edu.my or @student.mmu.edu.my)."

        elif form_name == "subjects":
            selected_subjects = request.form.getlist("subjects")
            user.preferred_subjects = " , ".join (selected_subjects)

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

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# Run the app
if __name__ == "__main__":
    app.run(debug=True)