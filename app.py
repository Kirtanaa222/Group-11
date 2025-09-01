from flask import Flask, render_template, request, redirect, url_for, session 
from flask_sqlalchemy import SQLAlchemy 
from werkzeug.security import generate_password_hash, check_password_hash 
from werkzeug.utils import secure_filename
import os 

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sql.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False #disable modification tracking in SQLAlchemy (saves memory and improves performance)
app.secret_key = "supersecret" #encrypt the data that store in the users session
db = SQLAlchemy(app)

UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    faculty = db.Column(db.String(50), nullable=False)
    student_id = db.Column(db.String(10), unique=True, nullable=False)
    user_email = db.Column(db.String(50), unique=True, nullable=False)
    bio = db.Column(db.Text, nullable=True)
    avatar = db.Column(db.String(200), nullable=True)
    background = db.Column(db.String(200), nullable=True)

with app.app_context():
    db.create_all()

# ---------------- Routes ----------------

@app.route("/")
def home():
    return render_template("home.html", username=session.get("username"))

#sign up form
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":  #check if the user has summitted sighup form
        username = request.form["username"]
        password = request.form["password"]
        faculty = request.form["faculty"]
        student_id = request.form["student_id"]
        user_email = request.form["user_email"]

        # to check if the user exists in db
        if User.query.filter_by(username=username).first(): #do not use .all() bcs we want to check that db only has 1 username
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
            session["user_id"] = user.id
            session["username"] = user.username
            return redirect(url_for("profile"))
        else:
            return render_template("login.html", error="Invalid username or password.")
    return render_template("login.html")

#----------------------profile----------------------------
def is_mmu_email(email):
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
    if not is_mmu_email(user.user_email):
        mmu_reminder = "You haven't updated your MMU email yet. Click below to update."

    return render_template("profile.html",
                           username=user.username,
                           avatar=avatar,
                           background=background,
                           bio=bio,
                           mmu_reminder=mmu_reminder)

#------------------------------profile_info---------------------------------

@app.route("/profile_info/<int:user_id>", methods=["GET", "POST"])
def profile_info(user_id):
    user = User.query.get(user_id)
    if not user:
        return "User not found", 404

    avatar = user.avatar or "default_avatar.png"
    background = user.background or "default_bg.jpg"
    bio = user.bio or ""
    error = None

    email_editable = not is_mmu_email(user.user_email)

    if request.method == "POST":
        bio_text = request.form.get("bio", "")
        new_email = request.form.get("user_email")
        avatar_file = request.files.get("avatar")
        bg_file = request.files.get("background")

        user.bio = bio_text

        if avatar_file and allowed_file(avatar_file.filename):
            filename = secure_filename(avatar_file.filename)
            avatar_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            user.avatar = f"uploads/{filename}"

        if bg_file and allowed_file(bg_file.filename):
            filename = secure_filename(bg_file.filename)
            bg_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            user.background = f"uploads/{filename}"

        if new_email:
            if is_mmu_email(new_email):
                user.user_email = new_email
            else:
                error = "Please enter a valid MMU email (@mmu.edu.my or @student.mmu.edu.my)."

        db.session.commit()

    return render_template("profile_info.html",
                           user=user,
                           avatar=avatar,
                           background=background,
                           bio=bio,
                           error=error,
                           email_editable=email_editable)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# Run the app
if __name__ == "__main__":
    app.run(debug=True)
