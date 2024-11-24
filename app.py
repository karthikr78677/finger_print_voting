import sqlite3
import os
import hashlib
from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify
import secrets

app = Flask(__name__)

# SQLite database name
DATABASE = 'votes.db'

# Folder to store fingerprint images
UPLOAD_FOLDER = 'uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max file size: 16MB

# Generate a random secret key for session management (for security purposes)
app.config['SECRET_KEY'] = secrets.token_hex(16)

# Initialize database and create tables if not exist
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        
        # Create users table if it doesn't exist
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id TEXT NOT NULL UNIQUE,
                            fingerprint BLOB NOT NULL)''')
        conn.commit()
        
        # Create votes table if it doesn't exist
        cursor.execute('''CREATE TABLE IF NOT EXISTS votes (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id TEXT NOT NULL,
                            team TEXT NOT NULL,
                            FOREIGN KEY (user_id) REFERENCES users (user_id))''')
        conn.commit()

# Route for rendering the registration form
@app.route('/')
def index():
    return render_template('register.html')

# Route for handling registration
@app.route('/register', methods=['POST'])
def register_user():
    user_id = request.form['user_id']
    fingerprint = request.files['fingerprint']

    # Check if file is a valid image
    if not fingerprint or not fingerprint.filename.endswith('.png'):
        flash('Invalid file type. Only PNG files are allowed!', 'error')
        return redirect(url_for('index'))

    # Save the fingerprint image to the uploads folder
    fingerprint_filename = os.path.join(app.config['UPLOAD_FOLDER'], f"{user_id}_fingerprint.png")
    fingerprint.save(fingerprint_filename)

    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (user_id, fingerprint) VALUES (?, ?)", (user_id, fingerprint_filename))
            conn.commit()
        flash('User registered successfully!', 'success')
        return redirect(url_for('index'))
    except sqlite3.IntegrityError:
        flash('User ID already registered!', 'error')
        return redirect(url_for('index'))

# Route for handling login and fingerprint verification

@app.route('/login', methods=['POST', 'GET'])
def login_user():
    if request.method == 'POST':
        user_id = request.form['user_id']
        fingerprint = request.files['fingerprint']

        # Ensure a fingerprint file was uploaded
        if not fingerprint:
            flash('Please upload a fingerprint image.', 'error')
            return redirect(url_for('login_user'))

        # Authenticate user using the user_id and fingerprint
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
            user = cursor.fetchone()

            if user:
                # Retrieve the stored fingerprint file path
                stored_fingerprint = user[2]  # Assuming the stored path is in the third column (index 2)

                # Save the uploaded fingerprint temporarily
                uploaded_fingerprint_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{user_id}_temp_fingerprint.png")
                fingerprint.save(uploaded_fingerprint_path)

                try:
                    # Compare the uploaded fingerprint hash with the stored one
                    if hash_file(uploaded_fingerprint_path) == hash_file(stored_fingerprint):
                        # If they match, log the user in
                        session['user_id'] = user_id
                        flash('Login successful!', 'success')
                        return redirect(url_for('vote'))  # Redirect to voting page
                    else:
                        flash('Fingerprint mismatch. Please try again.', 'error')
                        return redirect(url_for('login_user'))  # Redirect to login page if fingerprints don't match
                finally:
                    # Ensure the temporary file is deleted after verification
                    if os.path.exists(uploaded_fingerprint_path):
                        os.remove(uploaded_fingerprint_path)
            else:
                flash('User not found!', 'error')
                return redirect(url_for('login_user'))  # Redirect to login page if user not found

    return render_template('login.html')



# Simple comparison using file hash (for better accuracy than file path comparison)
def verify_fingerprint(stored_fingerprint, uploaded_fingerprint):
    # Generate file hashes for both the stored and uploaded fingerprint images
    stored_hash = hash_file(stored_fingerprint)
    uploaded_hash = hash_file(uploaded_fingerprint)
    return stored_hash == uploaded_hash



# Helper function to hash a file
def hash_file(file_path):
    """Generate hash for the fingerprint image to compare content"""
    hash_obj = hashlib.md5()
    with open(file_path, 'rb') as file:
        while chunk := file.read(4096):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

# Route for voting page
@app.route('/vote', methods=['GET'])
def vote_page():
    if 'user_id' not in session:
        flash('You need to log in first!', 'error')
        return redirect(url_for('login_user'))  # Redirect to login if no user_id in session
    return render_template('vote.html')

# Route for handling voting
@app.route('/vote', methods=['POST'])
def vote():
    if 'user_id' not in session:
        flash('You need to log in first!', 'error')
        return redirect(url_for('login_user'))  # Redirect to login if no user_id in session

    user_id = session['user_id']  # Get user_id from session
    team = request.form['team']

    # Check if the user has already voted
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM votes WHERE user_id = ?", (user_id,))
        existing_vote = cursor.fetchone()

        if existing_vote:
            flash('You have already voted!', 'error')
            return redirect(url_for('vote_page'))  # Redirect to the vote page if user already voted

        # Record the vote
        cursor.execute("INSERT INTO votes (user_id, team) VALUES (?, ?)", (user_id, team))
        conn.commit()
        flash(f'Vote for {team} successfully recorded!', 'success')

        # Redirect to a different page after voting (e.g., homepage or a thank you page)
        return redirect(url_for('thank_you'))  # You can create a 'thank_you' page

# Route for viewing voting results
@app.route('/results', methods=['GET'])
def results():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''SELECT team, COUNT(*) as vote_count FROM votes
                          GROUP BY team ORDER BY vote_count DESC''')
        results = cursor.fetchall()

    # Pass the voting results to the results page template
    return render_template('results.html', results=results)

# Route for thank you page after voting
@app.route('/thank_you', methods=['GET'])
def thank_you():
    return render_template('thank_you.html')  # Create a simple thank_you.html page with a thank you message

if __name__ == '__main__':
    init_db()  # Initialize the database (if necessary)
    app.run(debug=True)
