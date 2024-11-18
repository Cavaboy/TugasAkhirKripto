from flask import Flask, request, render_template, redirect, url_for, session, flash, send_file
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet, InvalidToken
from werkzeug.utils import secure_filename
from PIL import Image, ImageTk
import tkinter as tk
from tkinter import filedialog
import io
import base64
import os


app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallback_secure_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Define the upload folder and ensure it exists
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


# Make sure this key remains consistent between sessions
if not os.path.exists('secret.key'):
    with open('secret.key', 'wb') as key_file:
        key_file.write(Fernet.generate_key())

with open('secret.key', 'rb') as key_file:
    encryption_key = key_file.read()
cipher = Fernet(encryption_key)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())

    user = db.relationship('User', backref=db.backref('notes', lazy=True))

# Helper functions for encryption and decryption
from Crypto.Cipher import AES
import base64

# Caesar Cipher Shift Function
def caesar_cipher(text, shift=3):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            encrypted_text += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted_text += char
    return encrypted_text

# Caesar Decryption Function
def caesar_decipher(encrypted_text, shift=3):
    return caesar_cipher(encrypted_text, -shift)

# AES Helper Functions
def pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

# Encrypt Function (Caesar + AES)
def encrypt_text(text):
    # Apply Caesar cipher first
    caesar_encrypted = caesar_cipher(text)
    
    # AES encryption
    cipher = AES.new(encryption_key[:16], AES.MODE_ECB)
    encrypted = base64.b64encode(cipher.encrypt(pad(caesar_encrypted).encode()))
    return encrypted.decode()

# Decrypt Function (AES + Caesar)
def decrypt_text(encrypted_text):
    try:
        # AES decryption
        cipher = AES.new(encryption_key[:16], AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_text)).decode())
        
        # Apply Caesar decipher to get original text
        original_text = caesar_decipher(decrypted)
        return original_text
    except (ValueError, KeyError):
        flash('Failed to decrypt some content. Data might be corrupted.', 'danger')
        return '[Decryption Error]'

# Function to hide a message in an image (encoding)
def hide_message_in_image(image_path, message, output_path):
    img = Image.open(image_path).convert("RGB")
    pixels = img.load()

    # Convert the message into binary format and add a delimiter
    message_bin = ''.join(format(ord(char), '08b') for char in message) + '1111111111111110'  # End delimiter

    # Check if the image can accommodate the message
    max_capacity = img.width * img.height * 3  # Each pixel has 3 color channels (RGB)
    if len(message_bin) > max_capacity:
        raise ValueError("Message is too large to be hidden in this image.")

    # Embed the message into the image by modifying the LSBs of the pixels
    msg_index = 0
    for i in range(img.height):
        for j in range(img.width):
            if msg_index >= len(message_bin):
                break
            r, g, b = pixels[j, i]
            # Modify LSB of each channel
            if msg_index < len(message_bin):
                r = (r & 0xFE) | int(message_bin[msg_index])  # Modify LSB of red channel
                msg_index += 1
            if msg_index < len(message_bin):
                g = (g & 0xFE) | int(message_bin[msg_index])  # Modify LSB of green channel
                msg_index += 1
            if msg_index < len(message_bin):
                b = (b & 0xFE) | int(message_bin[msg_index])  # Modify LSB of blue channel
                msg_index += 1
            pixels[j, i] = (r, g, b)

    img.save(output_path)

# Function to extract the hidden message from an image (decoding)
def extract_message_from_image(image_path):
    img = Image.open(image_path).convert("RGB")
    pixels = img.load()

    binary_message = ""
    for i in range(img.height):
        for j in range(img.width):
            r, g, b = pixels[j, i]
            binary_message += str(r & 1)
            binary_message += str(g & 1)
            binary_message += str(b & 1)

    delimiter = '1111111111111110'
    end_index = binary_message.find(delimiter)

    if end_index != -1:
        binary_message = binary_message[:end_index]
    else:
        raise ValueError("Delimiter not found. The message may be corrupted or not present.")

    # Convert binary back to characters
    message = ''.join(chr(int(binary_message[i:i + 8], 2)) for i in range(0, len(binary_message), 8))
    
    return message

# Encrypt File
def encrypt_file(file_path, encrypted_path):
    with open(file_path, 'rb') as file:
        file_data = file.read()
        encrypted_data = cipher.encrypt(file_data)
    
    with open(encrypted_path, 'wb') as file:
        file.write(encrypted_data)

# Decrypt File
def decrypt_file(encrypted_path, decrypted_path):
    with open(encrypted_path, 'rb') as file:
        encrypted_data = file.read()
        decrypted_data = cipher.decrypt(encrypted_data)
    
    with open(decrypted_path, 'wb') as file:
        file.write(decrypted_data)

# Routes
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['newUsername']
        password = request.form['newPassword']
        if not username.strip() or not password.strip():
            flash('Username and password cannot be empty.', 'danger')
            return redirect(url_for('register'))
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Username already exists or an error occurred: {str(e)}', 'danger')
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    notes = Note.query.filter_by(user_id=user_id).all()

    # Decrypt titles and content for display
    decrypted_notes = []
    for note in notes:
        decrypted_note = {
            'id': note.id,
            'title': decrypt_text(note.title),
            'content': decrypt_text(note.content),
            'timestamp': note.timestamp
        }
        decrypted_notes.append(decrypted_note)

    return render_template('dashboard.html', notes=decrypted_notes)

@app.route('/note/<int:note_id>')
def view_note(note_id):
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    note = Note.query.get_or_404(note_id)
    if note.user_id != session['user_id']:
        flash('You do not have permission to view this note.', 'danger')
        return redirect(url_for('dashboard'))

    decrypted_note = {
        'id': note.id,
        'title': decrypt_text(note.title),
        'content': decrypt_text(note.content),
        'timestamp': note.timestamp
    }

    return render_template('view-note.html', note=decrypted_note)

@app.route('/edit-note/<int:note_id>', methods=['GET', 'POST'])
def edit_note(note_id):
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    note = Note.query.get_or_404(note_id)
    if note.user_id != session['user_id']:
        flash('You do not have permission to edit this note.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        if not title.strip() or not content.strip():
            flash('Title and content cannot be empty.', 'danger')
            return redirect(url_for('edit_note', note_id=note_id))

        note.title = encrypt_text(title)
        note.content = encrypt_text(content)
        db.session.commit()
        flash('Note updated successfully!', 'success')
        return redirect(url_for('view_note', note_id=note.id))

    decrypted_note = {
        'id': note.id,
        'title': decrypt_text(note.title),
        'content': decrypt_text(note.content),
        'timestamp': note.timestamp
    }

    return render_template('edit-note.html', note=decrypted_note)

@app.route('/delete-note/<int:note_id>', methods=['POST'])
def delete_note(note_id):
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    note = Note.query.get_or_404(note_id)
    if note.user_id != session['user_id']:
        flash('You do not have permission to delete this note.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        db.session.delete(note)
        db.session.commit()
        flash('Note deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while deleting the note: {str(e)}', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/add-note', methods=['GET', 'POST'])
def add_note():
    if 'user_id' not in session:
        flash('Please log in to add a note.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        user_id = session['user_id']
        
        if not title.strip() or not content.strip():
            flash('Title and content cannot be empty.', 'danger')
            return redirect(url_for('add_note'))

        # Encrypt the title and content before storing
        encrypted_title = encrypt_text(title)
        encrypted_content = encrypt_text(content)

        new_note = Note(user_id=user_id, title=encrypted_title, content=encrypted_content)
        try:
            db.session.add(new_note)
            db.session.commit()
            flash('Note added successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while adding the note: {str(e)}', 'danger')
            return redirect(url_for('add_note'))
        
        return redirect(url_for('dashboard'))

    return render_template('add-note.html')

@app.route('/steganography', methods=['GET', 'POST'])
def steganography():
    if request.method == 'POST':
        if 'imageFile' not in request.files:
            flash('No file part')
            return redirect(request.url)

        image_file = request.files['imageFile']

        if image_file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if image_file:
            filename = secure_filename(image_file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(file_path)

            # Hide the message in the image
            secret_message = request.form['secretMessage']
            output_path = os.path.join(app.config['UPLOAD_FOLDER'], 'encoded_' + filename)

            try:
                hide_message_in_image(file_path, secret_message, output_path)
                flash('Message hidden successfully!')
                return send_file(output_path, as_attachment=True)
            except ValueError as e:
                flash(str(e))
                return redirect(request.url)

    return render_template('steganography_page.html')

@app.route('/extract-steganography', methods=['POST'])
def extract_steganography():
    if 'extractImageFile' not in request.files:
        flash('No file part')
        return redirect(request.url)

    image_file = request.files['extractImageFile']

    if image_file.filename == '':
        flash('No selected file')
        return redirect(request.url)

    if image_file:
        filename = secure_filename(image_file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image_file.save(file_path)

        # Extract the message from the image
        try:
            extracted_message = extract_message_from_image(file_path)
            flash('Message extracted successfully!')
            return render_template('extracted_message.html', message=extracted_message)
        except ValueError as e:
            flash(str(e))
            return redirect(request.url)

@app.route('/file-encryption', methods=['GET', 'POST'])
def file_encryption():
    if request.method == 'POST':
        if 'fileToEncrypt' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['fileToEncrypt']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_' + filename)
            file.save(file_path)

            # Encrypt the file
            encrypt_file(file_path, encrypted_path)
            flash('File encrypted successfully!')
            return send_file(encrypted_path, as_attachment=True)

    return render_template('file_encryption_page.html')

@app.route('/file-decryption', methods=['GET', 'POST'])
def file_decryption():
    if request.method == 'POST':
        if 'fileToDecrypt' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['fileToDecrypt']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            decrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted_' + filename)
            file.save(file_path)

            # Decrypt the file
            decrypt_file(file_path, decrypted_path)
            flash('File decrypted successfully!')
            return send_file(decrypted_path, as_attachment=True)

    return render_template('file_decryption_page.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

