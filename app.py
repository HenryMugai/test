import os
from flask import Flask, g, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from config import DB_CONFIG, SECRET_KEY
import mysql.connector

# -------------------------------
# Flask & Bcrypt setup
# -------------------------------
app = Flask(__name__)
bcrypt = Bcrypt(app)

app.secret_key = SECRET_KEY
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# -------------------------------
# Database connection
# -------------------------------
def get_db():
    if 'db' not in g:
        g.db = mysql.connector.connect(**DB_CONFIG)
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db:
        db.close()

# -------------------------------
# Utility functions
# -------------------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# -------------------------------
# Routes
# -------------------------------

@app.route('/')
def index():
    return redirect('/login')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        file = request.files.get('profile_image')

        if password != confirm_password:
            flash("Passwords do not match.", 'danger')
            return redirect('/signup')

        filename = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO users (name, email, phone, password_hash, image_filename)
                VALUES (%s, %s, %s, %s, %s)
            """, (name, email, phone, password_hash, filename))
            conn.commit()
            cur.close()
            flash("Account created successfully. Please log in.", 'success')
            return redirect('/login')
        except Exception as e:
            flash(f"Error creating account: {str(e)}", 'danger')
            return redirect('/signup')

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password_input = request.form['password']

        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
            cur.close()

            if user and bcrypt.check_password_hash(user[4], password_input):
                session['user_id'] = user[0]
                session['name'] = user[1]
                session['email'] = user[2]
                session['phone'] = user[3]
                session['image'] = user[5]
                return redirect('/dashboard')
            else:
                flash('Invalid credentials.', 'danger')
                return redirect('/login')
        except Exception as e:
            flash(f"Login error: {str(e)}", 'danger')
            return redirect('/login')

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('dashboard.html', user=session)


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    user_id = session['user_id']

    if request.method == 'POST':
        # Handle profile image update
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                cur = db.cursor()
                cur.execute("UPDATE users SET image_filename = %s WHERE id = %s", (filename, user_id))
                db.commit()
                cur.close()

                session['image'] = filename
                flash("Profile image updated successfully.", 'success')
            else:
                flash("Invalid image file.", 'danger')

        # Handle password update
        elif 'current_password' in request.form:
            current_password = request.form['current_password']
            new_password = request.form['new_password']
            confirm_new_password = request.form['confirm_new_password']

            cur = db.cursor()
            cur.execute("SELECT password_hash FROM users WHERE id = %s", (user_id,))
            result = cur.fetchone()
            cur.close()

            if result and bcrypt.check_password_hash(result[0], current_password):
                if new_password == confirm_new_password:
                    new_hashed = bcrypt.generate_password_hash(new_password).decode('utf-8')
                    cur = db.cursor()
                    cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hashed, user_id))
                    db.commit()
                    cur.close()
                    flash("Password updated successfully.", "success")
                else:
                    flash("New passwords do not match.", "danger")
            else:
                flash("Current password is incorrect.", "danger")

    return render_template('profile.html', user=session)


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect('/login')


# -------------------------------
# Run the App
# -------------------------------
if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)

