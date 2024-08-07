from flask import Flask, request, render_template, session, redirect, url_for, flash

from keras.models import load_model
from keras.models import model_from_json
import json
from tensorflow.keras.preprocessing import sequence
from flask_mysqldb import MySQL
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
import requests
import csv
import os
import threading

app = Flask(__name__)
app.secret_key = 'skripsi123'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'db_skripsi'
mysql = MySQL(app)

vocab_file = 'vocabdatasetskripsi.json' 

with open(vocab_file, 'r') as f:
    vocabulary = json.load(f)

with open('modeldatasetskripsi.json', 'r') as json_file:
    load_model_json = json_file.read()

load_model = model_from_json(load_model_json)
load_model.load_weights("model_weightssdatasets.h5")

def url_to_sequence(url, vocabulary, max_url_len):
    url_int_tokens = [vocabulary.get(x, 0) for x in url[:max_url_len] if x in vocabulary]
    return sequence.pad_sequences([url_int_tokens], maxlen=max_url_len)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        email = request.form['email']
        password = request.form['password']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM user WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user[4], password): 
            session['is_logged_in'] = True
            session['user_id'] = user[0]
            session['username'] = user[2]
            session['namalengkap'] = user[1]
            session['email'] = email
            return redirect('/uhalaman') 
        else:
            error = 'Email atau password salah'
            return render_template('hlogin.html', error=error)

    return render_template('hlogin.html', error=None) 

@app.route('/')
def home():
    return render_template('hindex.html', result=None)

@app.route('/hdata')
def hdata():
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '', type=str)
    per_page = 6 
    offset = (page - 1) * per_page

    cursor = mysql.connection.cursor()

    if search_query:
        cursor.execute(
            "SELECT * FROM dataset WHERE url LIKE %s ORDER BY id DESC LIMIT %s OFFSET %s",
            ('%' + search_query + '%', per_page, offset)
        )
        dataset = cursor.fetchall()

        cursor.execute("SELECT COUNT(*) FROM dataset WHERE url LIKE %s", ('%' + search_query + '%',))
        total_entries = cursor.fetchone()[0]
    else:
        cursor.execute("SELECT * FROM dataset ORDER BY id DESC LIMIT %s OFFSET %s", (per_page, offset))
        dataset = cursor.fetchall()

        cursor.execute("SELECT COUNT(*) FROM dataset")
        total_entries = cursor.fetchone()[0]

    total_pages = (total_entries + per_page - 1) // per_page

    today_date = datetime.now().date()
    cursor.execute("SELECT COUNT(*) FROM dataset WHERE DATE(date) = %s", (today_date,))
    reports_today = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM dataset")
    total_url_count = cursor.fetchone()[0]
    cursor.close()

    return render_template('hdata.html', dataset=dataset, page=page, total_pages=total_pages, search_query=search_query, reports_today=reports_today, total_url_count=total_url_count)

@app.route('/htentang')
def htentang():
    return render_template('htentang.html', result=None)

@app.route('/uhalaman')
def uhalaman():
    if 'is_logged_in' in session:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM dataset WHERE submitted = %s", (session['username'],))
        user_report_count = cursor.fetchone()[0]
        cursor.close()

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM dataset")
        total_url_count = cursor.fetchone()[0]
        cursor.close()

        return render_template('uhalaman.html', user_report_count=user_report_count, total_url_count=total_url_count)
    return redirect('/hlogin')

@app.route('/report', methods=['POST'])
def report():

    url = request.form['url']
    
    if not url:
        flash("Harap masukkan URL", "danger")
        return redirect(url_for('uhalaman'))
    if not (url.startswith('http://') or url.startswith('https://')) or url in ['http://', 'https://']:
        flash("Harap masukkan URL yang benar", "danger")
        return redirect(url_for('uhalaman'))
    
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM dataset WHERE url = %s", (url,))
    existing_url = cursor.fetchone()
    cursor.close()

    if existing_url:
        flash("URL yang Anda masukkan sudah ada", "danger")
        return redirect(url_for('uhalaman'))

    max_url_len = 150
    X_manual = url_to_sequence(url, vocabulary, max_url_len)
    target_proba = load_model.predict(X_manual, batch_size=1)

    # Jika hasil prediksi phishing, simpan ke database
    if target_proba[0] > 0.5:
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO dataset (url, submitted, date) VALUES (%s, %s, %s)", (url, session['username'], datetime.now()))
        mysql.connection.commit()
        cursor.close()
        flash("Report URL berhasil, terima kasih!", "success")
    else:
        flash("URL yang Anda masukkan tidak terindikasi phishing", "warning")

    return redirect(url_for('uhalaman'))

@app.route('/hlogin')
def hlogin():
    return render_template('hlogin.html')

@app.route('/ureport')
def ureport():
    if 'is_logged_in' in session:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM dataset WHERE submitted = %s ORDER BY id DESC", (session['username'],))
        user_entries = cursor.fetchall()
        cursor.close()
        return render_template('ureport.html', user_entries=user_entries)
    return redirect('/hlogin')

@app.route('/delete-url/<url_id>', methods=['POST'])
def delete_url(url_id):
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM dataset WHERE id = %s", (url_id,))
    mysql.connection.commit()
    cursor.close()
    return redirect(url_for('ureport'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        namalengkap = request.form['namalengkap']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if not namalengkap or not username or not email or not password:
            flash("Lengkapi semua data diri untuk melakukan pendaftaran.", "danger")
            return render_template('hlogin.html')

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM user WHERE username = %s OR email = %s", (username, email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            flash("Username atau email sudah terdaftar, silahkan cek kembali", "danger")
            return render_template('hlogin.html')

        else:
            hashed_password = generate_password_hash(password)
            cursor.execute("INSERT INTO user (namalengkap, username, email, password) VALUES (%s, %s, %s, %s)", (namalengkap, username, email, hashed_password))
            mysql.connection.commit()
            cursor.close()
            flash("Registrasi berhasil, silahkan login.", "success")
            return redirect('/login')

    return render_template('hlogin.html')

@app.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():
    if 'is_logged_in' not in session:
        return redirect(url_for('hlogin'))

    if request.method == 'POST':
        namalengkap = request.form['namalengkap']
        username = request.form['username']
        password = request.form['password']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM user WHERE username = %s AND user_id != %s", (username, session['user_id'],))
        existing_user = cursor.fetchone()
        
        if existing_user:
            flash("Username sudah dipakai, silahkan pilih username lain.", "danger")
            return render_template('edit_profile.html')
        
        hashed_password = generate_password_hash(password)

        cursor.execute("""
            UPDATE user 
            SET namalengkap = %s, username = %s, password = %s 
            WHERE user_id = %s
        """, (namalengkap, username, hashed_password, session['user_id']))
        
        cursor.execute("""
            UPDATE dataset
            SET submitted = %s
            WHERE submitted = %s
        """, (username, session['username']))
        
        mysql.connection.commit()
        cursor.close()

        session['namalengkap'] = namalengkap
        session['username'] = username

        flash("Profil berhasil diperbarui.", "success")
        return redirect(url_for('edit_profile'))

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT namalengkap, username FROM user WHERE user_id = %s", (session['user_id'],))
    user_data = cursor.fetchone()
    cursor.close()

    return render_template('edit_profile.html', namalengkap=user_data[0], username=user_data[1])

# Route prediksi
@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']

    if not url:
        flash("Harap masukkan URL", "danger")
        return redirect(url_for('home'))
    if not (url.startswith('http://') or url.startswith('https://')) or url in ['http://', 'https://']:
        flash("Harap masukkan URL yang benar", "danger")
        return redirect(url_for('home'))

    max_url_len = 150
    X_manual = url_to_sequence(url, vocabulary, max_url_len)
    target_proba = load_model.predict(X_manual, batch_size=1)
    
    def print_result(proba):
        if proba > 0.5:
            return "phishing"
        else:
            return "sah"
    
    result = print_result(target_proba[0])
    return render_template('hindex.html', url=url, result=result)

# # proses klasifikasi file CSV, simpan data jika phishing
# def process_csv_and_store_data(filename):
#     with app.app_context():
#         try:
#             if not os.path.exists(filename):
#                 print(f"File {filename} does not exist.")
#                 return

#             print(f"Processing file: {filename}")

#             with open(filename, mode='r') as file:
#                 csv_reader = csv.reader(file)
#                 headers = next(csv_reader)  # Read header

#                 if headers[0].strip().lower() != 'url':
#                     print("Unexpected CSV header. Expected a header named 'url'.")
#                     return

#                 print(f"Headers: {headers}")

#                 max_url_len = 150
#                 db = mysql.connection
#                 cursor = db.cursor()

#                 inserted_count = 0
#                 processed_count = 0
#                 existing_phishing_count = 0

#                 for row in csv_reader:
#                     if len(row) < 1 or not row[0].strip():
#                         print("Skipping empty row")
#                         continue

#                     url = row[0].strip()  # Clean and get URL

#                     # Check if URL is already in the database
#                     cursor.execute("SELECT COUNT(*) FROM dataset WHERE url = %s", (url,))
#                     count = cursor.fetchone()[0]

#                     if count == 0:  # URL is not in the database
#                         # Predict and possibly insert
#                         X_manual = url_to_sequence(url, vocabulary, max_url_len)
#                         target_proba = load_model.predict(X_manual, batch_size=1)
                        
#                         if target_proba[0][0] > 0.5:  # URL is considered phishing
#                             cursor.execute(
#                                 "INSERT INTO dataset (url, submitted, date) VALUES (%s, %s, %s)",
#                                 (url, 'PhishTank', datetime.now())
#                             )
#                             inserted_count += 1
#                             print(f"Inserted URL: {url}")
#                     else:
#                         existing_phishing_count += 1

#                     processed_count += 1

#                 db.commit()
#                 cursor.close()

#                 print(f"Total URLs processed: {processed_count}")
#                 print(f"Total URLs inserted: {inserted_count}")
#                 print(f"Total phishing URLs not inserted because they already exist: {existing_phishing_count}")

#         except Exception as e:
#             print(f"Error processing CSV file: {e}")

# # Run CSV processing only once at the start of the application
# def run_csv_processing_once():
#     process_csv_and_store_data('dataa.csv')  # Change to your CSV filename

if __name__ == '__main__':
#    run_csv_processing_once()
   app.run(host='0.0.0.0', debug=True)