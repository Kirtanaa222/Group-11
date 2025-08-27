from flask import Flask, render_template, request, redirect, url_for, session 
from flask_sqlalchemy import SQLAlchemy 
from werkzeug.security import generate_password_hash, check_password_hash 

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sql.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False #disable modification tracking in SQLAlchemy (saves memory and improves performance)
app.secret_key = "supersecret" #encrypt the data that store in the users session
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    faculty = db.Column(db.String(50), nullable=False)
    student_id = db.Column(db.String(10), unique=True, nullable=False)
    user_email = db.Column(db.String(50), unique=True, nullable=False)

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
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["username"] = user.username
            return redirect(url_for("profile"))
        else:
            return render_template("login.html", error="Invalid username or password.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("profile.html", username=session["username"]) 

# Run the app
if __name__ == "__main__":
    app.run(debug=True)
