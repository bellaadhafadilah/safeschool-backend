from flask import Flask, render_template, request, jsonify, redirect, url_for
from pymongo import MongoClient
from flask_mail import Mail, Message
import bcrypt
import jwt
import random
from datetime import datetime, timedelta, timezone
from flask_cors import CORS
import hashlib
import smtplib
from functools import wraps
from email.mime.text import MIMEText
from google.oauth2 import id_token
from google.auth.transport import requests

app = Flask(__name__)
CORS(app)
app.config['JWT_SECRET'] = 'safeschool321'  
app.config['API_KEY'] = 'caps2025'


# Secret dan API key
JWT_SECRET = 'safeschool321'
API_KEY = 'caps2025'

# MongoDB connection
client = MongoClient("mongodb+srv://bellaadha:bellaadha125_@cluster0.sajjj.mongodb.net/safeschool?retryWrites=true&w=majority")
db = client.safeschool
users_collection = db.daftar_sekolah

# Fungsi hash email
def hash_email(email):
    return hashlib.sha256(email.encode('utf-8')).hexdigest()

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'safeschool49@gmail.com' 
app.config['MAIL_PASSWORD'] = 'unxtumdlpierllkg'  
app.config['MAIL_DEFAULT_SENDER'] = 'safeschool49@gmail.com'
mail = Mail(app)

@app.route('/')
def home():
    return "Selamat datang di API SafeSchool!"

# =====================
# ✅ REGISTER
# =====================
@app.route('/register', methods=['POST'])
def register():
    data = request.json

    # Validasi input
    if not data.get('namaSekolah') or not data.get('emailSekolah'):
        return jsonify({'success': False, 'message': 'Nama Sekolah dan Email wajib diisi!'}), 400

    if not data.get('password'):
        return jsonify({'success': False, 'message': 'Password wajib diisi!'}), 400

    email = data.get('emailSekolah')
    otp = str(random.randint(100000, 999999))

    # 🔒 Hash password
    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    data['password'] = hashed_password.decode('utf-8')

    # Simpan data + OTP
    db.otp_verifikasi.update_one(
        {'emailSekolah': email},
        {'$set': {
            'otp': otp,
            'created_at': datetime.now(timezone.utc),
            'data_registrasi': data
        }},
        upsert=True
    )

    print(f"📩 OTP untuk {email} adalah {otp}")

    if send_otp_email(email, otp):
        return jsonify({'success': True, 'message': 'OTP berhasil dikirim', 'email': email}), 201
    else:
        return jsonify({'success': False, 'message': 'Gagal mengirim OTP'}), 500

# =====================
# ✅ LOGIN (dengan API key + JWT hash email)
# =====================
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    print(f"📥 Data masuk dari frontend: {data}")

    api_key = request.headers.get('X-API-Key')  

    if api_key != app.config['API_KEY']:
        return jsonify({'success': False, 'message': 'API key tidak valid'}), 401

    email = data.get('emailSekolah')
    password = data.get('password')

    user = users_collection.find_one({'emailSekolah': email})
    if not user:
        return jsonify({'success': False, 'message': 'Email tidak ditemukan'}), 404

    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'success': False, 'message': 'Password salah'}), 401

    token = jwt.encode({
        'email_hash': hash_email(email), 
        'exp': datetime.now(timezone.utc) + timedelta(minutes=2)
    }, app.config['JWT_SECRET'], algorithm='HS256')

    response_user = {
        'namaSekolah': user.get('namaSekolah', ''),
        'tingkatPendidikan': user.get('tingkatPendidikan', ''),
        'alamat': user.get('alamat', ''),
        'emailSekolah': user.get('emailSekolah', ''),
        'namaAdmin': user.get('namaAdmin', ''),
        'profileImage': user.get('profileImage', ''),
    }

    return jsonify({
        'success': True,
        'message': 'Login berhasil',
        'token': token,
        'user': response_user
    }), 200


# =====================
# ✅ MIDDLEWARE JWT
# =====================
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({'message': 'Token tidak ditemukan!'}), 401

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            email_hash = data['email_hash']

            current_user = None
            for user in users_collection.find():
                if hash_email(user['emailSekolah']) == email_hash:
                    current_user = user
                    break

            if not current_user:
                return jsonify({'message': 'User tidak valid!'}), 403

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token kedaluwarsa!'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token tidak valid!'}), 403

        return f(current_user, *args, **kwargs)
    return decorated

# =====================
# ✅ PROFILE 
# =====================
@app.route('/profile', methods=['GET'])
@token_required
def profile(current_user):
    return jsonify({
        'namaSekolah': current_user['namaSekolah'],
        'emailSekolah': current_user['emailSekolah'],
        'tingkatPendidikan': current_user['tingkatPendidikan'],
        'namaAdmin': current_user['namaAdmin'],
    }), 200



# =========================
# ✅ GOOGLE LOGIN MOBILE
# =========================
@app.route('/authorize-google-mobile', methods=['POST'])
def authorize_google_mobile():
    if not request.is_json:
        return jsonify({'message': 'Request harus berupa JSON'}), 400

    data = request.get_json()
    token = data.get('id_token')

    if not token:
        return jsonify({'message': 'ID Token tidak ditemukan di body JSON'}), 400

    try:
        idinfo = id_token.verify_oauth2_token(
            token,
            requests.Request(),
            '176870905492-pks4est5ojn5cl3uvmfd2gffu8dfnml2.apps.googleusercontent.com'
        )

        email = idinfo['email']
        user = users_collection.find_one({'emailSekolah': email})

        if not user:
            return jsonify({'message': 'Email ini belum terdaftar di sistem SafeSchool. Silakan daftar terlebih dahulu.'}), 403

        jwt_token = jwt.encode({
            'email_hash': hash_email(email),
            'exp': datetime.now(timezone.utc) + timedelta(minutes=2),
            'iat': datetime.now(timezone.utc)
        }, JWT_SECRET, algorithm='HS256')

        return jsonify({'message': 'Login Google Mobile berhasil!', 'token': jwt_token})
    
    except ValueError as e:
        # Token tidak valid
        return jsonify({'message': f'Token tidak valid: {str(e)}'}), 400
    except Exception as e:
        # Error lainnya (misal database)
        return jsonify({'message': f'Gagal verifikasi token: {str(e)}'}), 500

      
    
def send_otp_email(to_email, otp):
    msg = MIMEText(f"Kode OTP SafeSchool Anda adalah: {otp}")
    msg['Subject'] = 'Verifikasi OTP SafeSchool'
    msg['From'] = 'youremail@gmail.com'
    msg['To'] = to_email

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login('safeschool49@gmail.com', 'unxtumdlpierllkg')  
        server.sendmail(msg['From'], [msg['To']], msg.as_string())
        server.quit()
        print("✅ Email OTP berhasil dikirim")
        return True
    except Exception as e:
        print(f"❌ Gagal kirim email: {e}")
        return False

@app.route('/send-otp', methods=['POST']) #registrasi
def send_otp():
    data = request.json
    email = data.get('emailSekolah')

    if not email:
        return jsonify({'success': False, 'message': 'Email wajib diisi'}), 400

    otp = str(random.randint(100000, 999999))

    # Simpan OTP ke MongoDB
    db.otp_verifikasi.update_one(
    {'emailSekolah': email},
    {'$set': {
        'otp': otp,
        'created_at': datetime.datetime.utcnow(),
        'data_registrasi': data  
    }},
    upsert=True
)


    # 🔍 CETAK OTP KE TERMINAL (log)
    print(f"📩 OTP untuk {email} adalah {otp}")

    # Kirim ke email
    if send_otp_email(email, otp):
        return jsonify({'success': True, 'message': 'OTP berhasil dikirim'}), 200
    else:
        return jsonify({'success': False, 'message': 'Gagal mengirim OTP'}), 500


@app.route('/verify-otp', methods=['POST']) 
def verify_otp():
    data = request.json
    email = data.get('emailSekolah')
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({'success': False, 'message': 'Email dan OTP wajib diisi'}), 400

    record = db.otp_verifikasi.find_one({'emailSekolah': email})
    if not record:
        return jsonify({'success': False, 'message': 'OTP tidak ditemukan'}), 404

    waktu_kirim = record.get('created_at')
    now = datetime.now(timezone.utc)


    if waktu_kirim.tzinfo is None:
        waktu_kirim = waktu_kirim.replace(tzinfo=timezone.utc)

    selisih = now - waktu_kirim

    if record['otp'] == str(otp).strip() and selisih.total_seconds() <= 600:
        data_registrasi = record.get('data_registrasi')

        if data_registrasi:
            data_registrasi['verifiedAt'] = datetime.now(timezone.utc)
            data_registrasi['isVerified'] = True

            # Simpan ke daftar_sekolah secara lengkap
            db.daftar_sekolah.insert_one(data_registrasi)

        # Hapus record OTP setelah sukses
        db.otp_verifikasi.delete_one({'emailSekolah': email})

        return jsonify({'success': True, 'message': 'OTP valid, akun berhasil dibuat'}), 200

    else:
        return jsonify({'success': False, 'message': 'OTP salah atau kadaluarsa'}), 400
# =====================
# ✅ RESET PASSWORD
# =====================
@app.route('/send-reset-password', methods=['POST'])
def send_reset_password():
    data = request.json
    email = data.get('emailSekolah')

    if not email:
        return jsonify({'success': False, 'message': 'Email wajib diisi'}), 400

    # Cek apakah email terdaftar
    user = users_collection.find_one({'emailSekolah': email})
    if not user:
        return jsonify({'success': False, 'message': 'Email tidak ditemukan'}), 404

    # Generate token + expiry
    token = str(random.randint(100000, 999999)) + hashlib.sha256(email.encode()).hexdigest()[:16]
    expiry = datetime.now(timezone.utc) + timedelta(minutes=10)

    # Simpan token ke database
    users_collection.update_one(
        {'emailSekolah': email},
        {'$set': {
            'reset_token': token,
            'token_expiry': expiry
        }}
    )

    # Kirim email reset password
    try:
        send_reset_email(email, token)
        return jsonify({'success': True, 'message': 'Email reset password berhasil dikirim'}), 200
    except Exception as e:
        print(f"Gagal mengirim email: {e}")
        return jsonify({'success': False, 'message': 'Gagal mengirim email reset password'}), 500
  

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = users_collection.find_one({'reset_token': token})
    
    if user and user.get('token_expiry'):
        token_expiry = user['token_expiry']

        # Pastikan token_expiry adalah timezone-aware
        if token_expiry.tzinfo is None:
            token_expiry = token_expiry.replace(tzinfo=timezone.utc)

        # Bandingkan setelah keduanya sama-sama timezone-aware
        if token_expiry > datetime.now(timezone.utc):
            if request.method == 'POST':
                new_password = request.form.get('new_password')
                confirm_password = request.form.get('confirm_password')

                if not new_password or not confirm_password:
                    return render_template('reset_password.html', token=token, error='Semua kolom harus diisi.')

                if new_password != confirm_password:
                    return render_template('reset_password.html', token=token, error='Password tidak cocok.')

                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

                users_collection.update_one(
                    {'emailSekolah': user['emailSekolah']},
                    {
                        '$set': {
                            'password': hashed_password.decode('utf-8'),
                            'reset_token': None,
                            'token_expiry': None
                        }
                    }
                )

                return render_template('reset_password.html', success='Password berhasil direset. Silakan login di aplikasi.')

            return render_template('reset_password.html', token=token)

    # Jika token tidak ditemukan atau sudah kedaluwarsa
    return render_template('reset_password.html', error='Token tidak valid atau sudah kedaluwarsa.')

# =====================
# ✅ SEND RESET EMAIL
# =====================
def send_reset_email(email, token):
    msg = Message('Reset Password', recipients=[email])
    msg.body = f"Klik link berikut untuk mereset password Anda: http://192.168.18.8:5000/reset-password/{token}"
    mail.send(msg)



# =====================
# ✅ JALANKAN APP
# =====================
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)