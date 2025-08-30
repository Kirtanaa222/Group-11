from flask import Flask, render_template, request, redirect, url_for, session, jsonify 
from flask_sqlalchemy import SQLAlchemy 
from werkzeug.security import generate_password_hash, check_password_hash 
from datetime import datetime
from flask import abort

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sql.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "supersecret"
db = SQLAlchemy(app)

# new database because needed for admin functionality
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    faculty = db.Column(db.String(50), nullable=False)
    student_id = db.Column(db.String(10), unique=True, nullable=False)
    user_email = db.Column(db.String(50), unique=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False) 

with app.app_context():
    db.create_all()

# Helper function to check if user is logged in or is admin
def is_logged_in_admin():
    user_id = session.get("user_id")
    if not user_id:
        return False
    user = User.query.get(user_id)
    return user and user.is_admin

# Admin routes- only accessible to admin users. so need to sign up first then manually set is_admin to True in the database
@app.route('/admin')
def admin_dashboard():
    if not is_logged_in_admin():
        abort(403)
    return render_template('admin.html')

@app.route('/admin/users', methods=['GET'])
def admin_get_users():
    if not is_logged_in_admin():
        abort(403)
    users = User.query.all()
    return jsonify([
        {
            'id': user.id,
            'username': user.username,
            'user_email': user.user_email,
            'is_verified': user.is_verified,
            'status': user.status,
            'created_at': user.created_at.isoformat()
        }
        for user in users
    ])

# Admin can verify users - only verified users can log in
@app.route('/admin/users/<int:user_id>/ban', methods=['PATCH'])
def admin_ban_user(user_id):
    if not is_logged_in_admin():
        abort(403)
    user = User.query.get_or_404(user_id)
    user.status = 'banned'
    db.session.commit()
    return jsonify({'message': f'User {user.user_email} banned'})

# Admin can unban users
@app.route('/admin/users/<int:user_id>/unban', methods=['PATCH'])
def admin_unban_user(user_id):
    if not is_logged_in_admin():
        abort(403)
    user = User.query.get_or_404(user_id)
    user.status = 'active'
    db.session.commit()
    return jsonify({'message': f'User {user.user_email} unbanned'})

@app.route("/")
def home():
    return render_template("home.html", username=session.get("username"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        faculty = request.form["faculty"]
        student_id = request.form["student_id"]
        user_email = request.form["user_email"]

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
                return render_template("login.html", error="Your account has been banned.")
            session["user_id"] = user.id
            session["username"] = user.username
            session["is_admin"] = user.is_admin
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