from flask import Flask, render_template, request, redirect, session, url_for, send_file
from datetime import datetime
import sqlite3
import os
import hashlib  
# from flask_session import Session

from difflib import SequenceMatcher

from cryptography.x509.oid import NameOID

from cryptography.fernet import Fernet

import uuid

import smtplib
from email.mime.text import MIMEText

# ==== DIGITAL SIGNATURE IMPORT ====
from pyhanko.sign import signers
from pyhanko.sign.signers import SimpleSigner
from pyhanko.sign.signers.pdf_signer import PdfSigner
from pyhanko.sign.general import load_cert_from_pemder
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from pyhanko.sign.signers import PdfSignatureMetadata

# ==== IMPORT UNTUK VERIFIKASI ====F
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.pdf_utils.reader import PdfFileReader
# =================================

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from PyPDF2 import PdfReader, PdfWriter
import io
import json

from werkzeug.security import generate_password_hash, check_password_hash

import secrets

from dotenv import load_dotenv

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

env_path = os.path.join(os.getcwd(), '.env')
load_dotenv(env_path)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB limit
app.config['SESSION_PERMANENT'] = False
# app.config['SESSION_TYPE'] = 'filesystem'  # simpan session di filesystem
app.config['SESSION_COOKIE_SECURE'] = False  # set True kalau pakai HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# app.config['SESSION_FILE_DIR'] = './flask_session'  # Folder untuk session

METADATA_SECRET = "rahasia_super_aman_123"

# Buat folder session
os.makedirs('./flask_session', exist_ok=True)

# Session(app)  # Inisialisasi Flask-Session

# Buat folder uploads jika belum ada
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'pdf'}

# KEY untuk enkripsi (HARUS tetap sama)
stego_key_env = os.getenv("STEGO_KEY")

if not stego_key_env:
    raise ValueError("STEGO_KEY tidak ditemukan di environment variables")

STEGO_KEY = stego_key_env.encode()
cipher = Fernet(STEGO_KEY)

def encrypt_message(message):
    return cipher.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message):
    return cipher.decrypt(encrypted_message.encode()).decode()

# =========================
# Helper
# =========================
def similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def embed_metadata(pdf_path, data_dict, secret_message=None):
    try:
        reader = PdfReader(pdf_path)
        writer = PdfWriter()

        # Copy semua halaman
        for page in reader.pages:
            writer.add_page(page)

        metadata = reader.metadata or {}

        # Tambahkan pesan rahasia jika ada
        if secret_message:
            data_dict["secret"] = secret_message

        metadata.update({
            "/HiddenData": json.dumps(data_dict)
        })

        writer.add_metadata(metadata)

        with open(pdf_path, "wb") as f:
            writer.write(f)

        return True

    except Exception as e:
        print("Error embed metadata:", e)
        return False
    
def extract_pdf_info(pdf_path):
    try:
        reader = PdfReader(pdf_path)
        metadata = reader.metadata

        if metadata:
            return {
                "author": metadata.get("/Author"),
                "creator": metadata.get("/Creator"),
                "producer": metadata.get("/Producer"),
                "title": metadata.get("/Title")
            }
        return None

    except Exception as e:
        print("Error extract pdf info:", e)
        return None

def embed_hidden_text_raw(pdf_path, hidden_text):
    try:
        print("MENULIS STEGO KE:", pdf_path)
        with open(pdf_path, "ab") as f:
            f.write(b"\n%%STEGO_START%%\n")
            f.write(hidden_text.encode())
            f.write(b"\n%%STEGO_END%%\n")
        print("STEGO BERHASIL DITULIS")
        return True
    
    except Exception as e:
        print("Error stego raw:", e)
        return False
    
def embed_text_in_pdf(input_path, output_path, text):
    try:
        reader = PdfReader(input_path)
        writer = PdfWriter()

        packet = io.BytesIO()
        first_page = reader.pages[0]

        width = float(first_page.mediabox.width)
        height = float(first_page.mediabox.height)

        can = canvas.Canvas(packet, pagesize=(width, height))
        can.setFont("Helvetica", 5)

        # tulis stego (JANGAN nutup konten utama)
        can.drawString(10, 10, "[STEGO AREA]")
        can.drawString(10, 5, text)

        can.save()
        packet.seek(0)

        overlay_pdf = PdfReader(packet)

        for i, page in enumerate(reader.pages):
            if i == 0:
                # 🔥 FIX: copy dulu page biar ga overwrite reference
                base_page = page
                base_page.merge_page(overlay_pdf.pages[0])
                writer.add_page(base_page)
            else:
                writer.add_page(page)

        with open(output_path, "wb") as f:
            writer.write(f)

        return True

    except Exception as e:
        print("Error embed visual stego:", e)
        return False

def extract_hidden_text_raw(pdf_path):
    try:
        with open(pdf_path, "rb") as f:
            data = f.read()

        start_marker = b"%%STEGO_START%%"
        end_marker = b"%%STEGO_END%%"

        start = data.find(start_marker)
        end = data.find(end_marker)

        if start != -1 and end != -1:
            hidden = data[start + len(start_marker):end]
            return hidden.decode().strip()
        
        return None

    except Exception as e:
        print("Error extract stego:", e)
        return None
    
def sign_metadata(data):
    private_key_data = os.getenv("PRIVATE_KEY").encode()

    private_key = serialization.load_pem_private_key(
        private_key_data,
        password=None
    )

    data_bytes = json.dumps(data, sort_keys=True).encode()

    signature = private_key.sign(
        data_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return signature.hex()

def send_verification_email(to_email, token):
    try:
        sender_email = os.getenv("EMAIL_USER")
        sender_password = os.getenv("EMAIL_PASS")

        verification_link = f"http://127.0.0.1:5000/verify-email/{token}"

        subject = "Verifikasi Akun Anda"
        body = f"Klik link berikut untuk verifikasi akun:\n{verification_link}"

        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = to_email

        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()

        print("Email berhasil dikirim!")

    except Exception as e:
        print("Error kirim email:", e)

def write_key_files():
    private_key = os.getenv("PRIVATE_KEY")
    certificate = os.getenv("CERTIFICATE")

    if not private_key or not certificate:
        raise ValueError("PRIVATE_KEY / CERTIFICATE belum diset di environment")

    with open("temp_private_key.pem", "w") as f:
        f.write(private_key)

    with open("temp_certificate.pem", "w") as f:
        f.write(certificate)

# =========================
# DIGITAL SIGN FUNCTION
# =========================
def sign_pdf(input_path, output_path, secret_message=None):
    try:
        # ===== STEP 1: HASH FILE ASLI =====
        with open(input_path, 'rb') as f:
            file_data = f.read()
            initial_hash = hashlib.sha256(file_data).hexdigest()

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data_string = initial_hash + timestamp
        metadata_signature = sign_metadata(data_string)

        doc_id = str(uuid.uuid4())

        hidden_data = {
            "doc_id": doc_id,
            "hash": initial_hash,
            "timestamp": timestamp,
            "signature": metadata_signature,
            "secret_message": secret_message
        }

        # ===== STEP 2: COPY KE FILE BARU (JANGAN TIMPA FILE ASLI!) =====
        temp_meta_path = input_path.replace(".pdf", "_meta.pdf")
        temp_embed_path = input_path.replace(".pdf", "_embed.pdf")

        # copy dulu
        reader = PdfReader(input_path)
        writer = PdfWriter()
        for p in reader.pages:
            writer.add_page(p)

        with open(temp_meta_path, "wb") as f:
            writer.write(f)

        # ===== STEP 3: EMBED METADATA =====
        embed_metadata(temp_meta_path, hidden_data)

        # ===== STEP 4: STEGO =====
        data_stego = {
            "doc_id": doc_id,
            "user": session.get("user_email"),
            "timestamp": timestamp
        }

        encrypted_msg = encrypt_message(json.dumps(data_stego))
        hidden_text = f"SECURE_DOC::{encrypted_msg}"

        embed_text_in_pdf(temp_meta_path, temp_embed_path, hidden_text)

        # ===== STEP 5: SIGN FILE YANG SUDAH FIX =====
        write_key_files()

        signer = SimpleSigner.load(
            key_file="temp_private_key.pem",
            cert_file="temp_certificate.pem",
            key_passphrase=None
        )

        with open(temp_embed_path, 'rb') as inf:
            writer = IncrementalPdfFileWriter(inf)

            meta = PdfSignatureMetadata(field_name='Signature1')

            pdf_signer = PdfSigner(meta, signer=signer)

            with open(output_path, 'wb') as outf:
                pdf_signer.sign_pdf(writer, output=outf)

        # ===== STEP 6: SIMPAN DB =====
        with open(output_path, 'rb') as f:
            final_hash = hashlib.sha256(f.read()).hexdigest()

        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            original_text = extract_text_from_pdf(input_path)

            c.execute("""
                INSERT INTO documents (filename, upload_time, file_hash, doc_id, content)
                VALUES (?, ?, ?, ?, ?)
            """, (
                os.path.basename(output_path),
                timestamp,
                final_hash,
                doc_id,
                original_text
            ))
            conn.commit()

        # cleanup
        for f in ["temp_private_key.pem", "temp_certificate.pem",
                  temp_meta_path, temp_embed_path]:
            if os.path.exists(f):
                os.remove(f)

        return True

    except Exception as e:
        print("ERROR SIGN:", e)
        return False
    
def extract_text_from_pdf(pdf_path):
    try:
        reader = PdfReader(pdf_path)
        full_text = ""

        for page in reader.pages:
            if page.extract_text():
                full_text += page.extract_text()

        return full_text

    except Exception as e:
        print("Error extract text:", e)
        return ""

def extract_metadata(pdf_path):
    try:
        reader = PdfReader(pdf_path)
        metadata = reader.metadata

        result = {}

        if metadata:
            result["author"] = metadata.get("/Author")
            result["creator"] = metadata.get("/Creator")
            result["producer"] = metadata.get("/Producer")

            if "/HiddenData" in metadata:
                result["hidden"] = json.loads(metadata["/HiddenData"])

        return result

    except Exception as e:
        print("Error extract metadata:", e)
        return None 
 

# =========================
# Init Database
# =========================
def init_db():
    with sqlite3.connect('database.db', timeout=10) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT,
                upload_time TEXT,
                file_hash TEXT,
                doc_id TEXT,
                content TEXT
            )
        ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id TEXT,
            email TEXT UNIQUE,
            phone TEXT,
            password TEXT,
            is_verified INTEGER DEFAULT 0,
            verification_token TEXT
        )
        ''')
    conn.commit()

init_db()

# =========================
# HOME (ROOT)
# =========================
@app.route("/")
def home():
    return redirect(url_for("login"))

# =========================
# LOGIN
# =========================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['username']  # nanti bisa kamu rename jadi email
        password = request.form['password']

        with sqlite3.connect('database.db', timeout=10) as conn:
            c = conn.cursor()
            c.execute("SELECT password, is_verified FROM users WHERE email = ?", (email,))
            user = c.fetchone()

        if user:
            stored_password = user[0]
            is_verified = user[1]

            if not check_password_hash(stored_password, password):
                return render_template('login.html',
                                    message="Password salah!",
                                    status="danger")

            if is_verified == 0:
                return render_template('login.html',
                                    message="Akun belum diverifikasi! Cek email kamu.",
                                    status="warning")

            session['logged_in'] = True
            session['user_email'] = email
            return redirect(url_for('list_documents'))
        
        else:
            return render_template('login.html',
                                   message="Login gagal!",
                                   status="danger")

    return render_template('login.html')

# =========================
# REGISTER
# =========================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        employee_id = request.form['employee_id']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']

        # HASH PASSWORD
        hashed_password = generate_password_hash(password)

        try:
            with sqlite3.connect('database.db', timeout=10) as conn:
                c = conn.cursor()
                token = secrets.token_urlsafe(32)  # Generate token unik untuk verifikasi
                c.execute('''
                    INSERT INTO users (employee_id, email, phone, password, verification_token, is_verified)
                    VALUES (?, ?, ?, ?, ?, 1)
                ''', (employee_id, email, phone, hashed_password, token))
                conn.commit()

            # Kirim email verifikasi
            # send_verification_email(email, token)

            verification_link = f"http://127.0.0.1:5000/verify-email/{token}"

            return render_template('check_email.html')

        except Exception as e:
            print(e)
            return render_template('register.html',
                                   message="Email sudah terdaftar!",
                                   status="danger")

    return render_template('register.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    with sqlite3.connect('database.db', timeout=10) as conn:
        c = conn.cursor()

    # Cari user berdasarkan token
    c.execute("SELECT id FROM users WHERE verification_token = ?", (token,))
    user = c.fetchone()

    if user:
        # Update jadi verified
        c.execute("""
            UPDATE users 
            SET is_verified = 1, verification_token = NULL 
            WHERE id = ?
        """, (user[0],))
        conn.commit()
       

        return render_template("verify_success.html")
    else:
        conn.close()
        return "Token tidak valid atau sudah digunakan."

# =========================
# UPLOAD & SIGN
# =========================
@app.route("/upload", methods=["GET", "POST"])
def upload_file():
    if not session.get("logged_in"):
        print("Session tidak ditemukan, redirect ke login")  # untuk debug
        return redirect(url_for("login"))
    
    print(f"Session logged_in: {session.get('logged_in')}")  # untuk debug
    
    if request.method == "POST":
        file = request.files["file"]

        secret_message = request.form.get("secret_message")

        if file and allowed_file(file.filename):
            # Bersihkan filename dari path
            filename = os.path.basename(file.filename)
            input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(input_path)

            output_filename = filename.replace(".pdf", "_signed.pdf")
            output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

            if sign_pdf(input_path, output_path, secret_message):
                signed_filename = output_filename  # Simpan nama file
                return render_template('upload.html',
                         message="File berhasil diupload dan ditandatangani!",
                         status="success",
                         signed_file=signed_filename)  # Kirim ke template
            else:
                return render_template('upload.html',
                                     message="Gagal menandatangani file!",
                                     status="danger")

    return render_template("upload.html", signed_file=None)

# =========================
# VERIFY SIGNATURE
# =========================
@app.route('/verify', methods=['GET', 'POST'])
def verify_file():
    if request.method == 'POST':
        file = request.files['file']

        secret_message = request.form.get("secret_message")

        if file and allowed_file(file.filename):
            filename = str(uuid.uuid4()) + ".pdf"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            try:
                # ===== HITUNG HASH FILE YANG DIPERIKSA =====
                with open(filepath, 'rb') as f:
                    file_data = f.read()
                    current_hash = hashlib.sha256(file_data).hexdigest()
                # ===========================================

                metadata_all = extract_metadata(filepath)
                hidden_data = metadata_all.get("hidden") if metadata_all else None

                metadata_doc_id = hidden_data.get("doc_id") if hidden_data else None

                author = metadata_all.get("author") if metadata_all else None
                creator = metadata_all.get("creator") if metadata_all else None
                producer = metadata_all.get("producer") if metadata_all else None          

                # ===== FIX STEGO =====
                stego_message = None

                # Ambil stego dari RAW (cara lama)
                stego_raw = extract_hidden_text_raw(filepath)

                # Ambil stego dari TEKS PDF (cara baru 🔥)
                stego_text = extract_stego_from_text(filepath)

                print("DEBUG STEGO RAW:", stego_raw)
                print("DEBUG STEGO TEXT:", stego_text)

                # Prioritas: kalau stego visual ada, pakai itu
                if stego_text:
                    try:
                        stego_raw_data = decrypt_message(stego_text)
                        stego_json = json.loads(stego_raw_data)

                        stego_user = stego_json.get("user")
                        stego_doc_id = stego_json.get("doc_id")
                        stego_time = stego_json.get("timestamp")

                        stego_message = stego_raw_data  # kalau masih mau ditampilkan mentah

                    except:
                        stego_message = "Gagal decrypt stego visual"
                        stego_user = None
                        stego_doc_id = None
                        stego_time = None
                elif stego_raw:
                    try:
                        raw_msg = stego_raw.replace("SECURE_DOC::", "")

                        if raw_msg != "EMPTY":
                            stego_raw_data = decrypt_message(raw_msg)
                            stego_json = json.loads(stego_raw_data)

                            stego_user = stego_json.get("user")
                            stego_doc_id = stego_json.get("doc_id")
                            stego_time = stego_json.get("timestamp")

                            stego_message = stego_raw_data

                        else:
                            stego_message = "(kosong)"
                            stego_user = None
                            stego_doc_id = None
                            stego_time = None

                    except:
                        stego_message = "Gagal decrypt stego raw"
                        stego_user = None
                        stego_doc_id = None
                        stego_time = None
                else:
                    stego_message = None
                        

                if hidden_data:
                    metadata_hash = hidden_data.get("hash")
                    metadata_timestamp = hidden_data.get("timestamp")
                    metadata_signature = hidden_data.get("signature")

                    # Recreate signature
                    data_string = metadata_hash + metadata_timestamp
                    recalculated_signature = sign_metadata(data_string)

                    metadata_valid = (metadata_signature == recalculated_signature)

                    print("DEBUG - Metadata valid:", metadata_valid)
                else:
                    metadata_hash = None
                    metadata_valid = False
                
                # ===== AMBIL HASH ASLI DARI DATABASE =====
                with sqlite3.connect('database.db', timeout=10) as conn:
                    c = conn.cursor()
                c.execute("SELECT file_hash, doc_id FROM documents WHERE doc_id = ?", (metadata_doc_id,))
                result = c.fetchone()
                
                # ==========================================
                                
                # ===== CEK IDENTITAS DOKUMEN =====
                if not metadata_doc_id:
                    message = "Dokumen tidak memiliki identitas (bukan dari sistem)"
                    status_msg = "warning"

                elif not result:
                    message = "Dokumen tidak terdaftar di sistem"
                    status_msg = "warning"

                else:
                    # ===== AMBIL TEKS ASLI DARI DB =====
                    with sqlite3.connect('database.db', timeout=10) as conn:
                        c = conn.cursor()
                    c.execute("SELECT content FROM documents WHERE doc_id = ?", (metadata_doc_id,))
                    db_result = c.fetchone()
                    

                    original_text = db_result[0] if db_result else ""
                    current_text = extract_text_from_pdf(filepath)

                    # ===== PERBANDINGAN SEDERHANA =====
                    score = similarity(original_text, current_text)

                    print("DEBUG SIMILARITY:", score)

                    if score > 0.95:
                        message = f"Dokumen ASLI (kemiripan {round(score*100,2)}%)"
                        status_msg = "success"

                    elif score > 0.7:
                        message = f"Dokumen mengalami perubahan sebagian (kemiripan {round(score*100,2)}%)"
                        status_msg = "warning"

                    else:
                        message = f"Dokumen sudah dimodifikasi signifikan (kemiripan {round(score*100,2)}%)"
                        status_msg = "danger"

                return render_template(
                    'verify.html',
                    message=message,
                    status=status_msg,
                    doc_id=metadata_doc_id,
                    timestamp=hidden_data.get("timestamp") if hidden_data else None,
                    metadata_status="Valid" if metadata_valid else "Tidak Valid",
                    stego_message=stego_message,
                    author=author,
                    creator=creator,
                    producer=producer,
                    original_owner=stego_user
                )

                return response
            
            except Exception as e:
                print(f"Error verifying: {e}")
                return render_template(
                    'verify.html',
                    message="Error membaca file PDF",
                    status="danger"
                )
            
            finally:
                if os.path.exists(filepath):
                    os.remove(filepath)
                    
    return render_template('verify.html')

def extract_stego_from_text(pdf_path):
    try:
        text = extract_text_from_pdf(pdf_path)

        if "[STEGO AREA]" in text and "SECURE_DOC::" in text:
            area_part = text.split("[STEGO AREA]")[1]
            stego_part = area_part.split("SECURE_DOC::")[1]
            stego_clean = stego_part.split()[0]
            return stego_clean

        return None

    except:
        return None
    
# =========================
# LIST DOCUMENTS
# =========================
@app.route('/documents')
def list_documents():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    with sqlite3.connect('database.db', timeout=10) as conn:
        c = conn.cursor()
    c.execute("SELECT id, filename, doc_id, upload_time FROM documents ORDER BY id DESC")
    documents = c.fetchall()
    

    return render_template('documents.html', documents=documents)

# =========================
# LOGOUT
# =========================
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# =========================
# DOWNLOAD FILE
# =========================
@app.route('/download/<filename>')
def download_file(filename):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # Pastikan file ada di folder uploads
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        from flask import send_file
        return send_file(file_path, as_attachment=True)
    else:
        return "File tidak ditemukan", 404

# =========================
# RUN APP
# =========================
if __name__ == '__main__':
    app.run(debug=True)