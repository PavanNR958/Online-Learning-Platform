from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import webbrowser

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    otp = db.Column(db.String(6))
    is_student = db.Column(db.Boolean, default=True)


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email is already registered. Please log in.', 'danger')
            return redirect(url_for('home'))
        else:
            password = request.form.get('password')
            hashed_password = bcrypt.generate_password_hash(
                password).decode('utf-8')
            otp = str(random.randint(100000, 999999)) 
            new_user = User(email=email, password=hashed_password,
                            is_verified=False, otp=otp)
            db.session.add(new_user)
            db.session.commit()
            session['email'] = email  
            send_otp_email(email, otp)  
            flash(
                'Your account has been created! Please check your email for the OTP.', 'success')
            return redirect(url_for('verify'))

    return render_template('signup.html')


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        otp = request.form.get('otp')
        user = User.query.filter_by(email=session['email']).first()

        if user and otp == user.otp:
            user.is_verified = True
            db.session.commit()
            flash('Email verification successful! You can now log in.', 'success')
            return redirect(url_for('home')) 
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('verify.html')


@app.route('/verify1', methods=['GET', 'POST'])
def verify1():
    if request.method == 'POST':

        return redirect(url_for('student_dashboard'))

    return render_template('verify1.html')


@app.route('/verify2', methods=['GET', 'POST'])
def verify2():
    if request.method == 'POST':

        return redirect(url_for('teacher_dashboard'))

    return render_template('verify2.html')


def send_otp_email(to_email, otp):
    msg = MIMEMultipart()
    msg['From'] = 'your_email@gmail.com'
    msg['To'] = to_email
    msg['Subject'] = 'Verification OTP'

    body = """
<html>
  <body style="font-family: Arial, sans-serif; padding: 20px; background-color: #f4f4f4;">
    <div style="max-width: 400px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.2;">
      <h1 style="font-size: 24px; color: #007BFF;">Verification OTP</h1>
      <p style="font-size: 18px; line-height: 1.6;">Your OTP is: <span style="font-weight: bold; color: #007BFF;">{}</span></p>
    </div>
  </body>
</html>
""".format(otp)

    msg.attach(MIMEText(body, 'html'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()

    server.login('mehulnaik16@gmail.com', 'allletrgoedajdop')
    server.sendmail('mehulnaik16@gmail.com', to_email, msg.as_string())
    server.quit()


@app.route('/student_dashboard', methods=['GET', 'POST'])
def student_dashboard():
    if request.method == 'POST':
        return redirect(url_for('student_dashboard'))

    return render_template('student_dashboard.html')


@app.route('/teacher_dashboard', methods=['GET', 'POST'])
def teacher_dashboard():
    if request.method == 'POST':
        return redirect(url_for('teacher_dashboard'))

    return render_template('teacher_dashboard.html')


@app.route('/subscribed', methods=['GET', 'POST'])
def subscribed():
    if request.method == 'POST':
        return redirect(url_for('student_dashboard'))

    return render_template('subscribed.html')


@app.route('/subscribe', methods=['GET', 'POST'])
def subscribe():
    if request.method == 'POST':
        return redirect(url_for('subscribed1.html'))

    return render_template('subscribed1.html')


@app.route('/student_login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        email = request.form.get('email')

        otp = str(random.randint(100000, 999999))
        session['email'] = email
        send_otp_email(email, otp)
        flash(
            'Your account has been created! Please check your email for the OTP.', 'success')
        return redirect(url_for('verify1'))

    return render_template('student_login.html')


@app.route('/teacher_login', methods=['GET', 'POST'])
def teacher_login():
    if request.method == 'POST':
        email = request.form.get('email')
        otp = str(random.randint(100000, 999999))
        send_otp_email(email, otp)
        session['email'] = email
        flash('New OTP sent. Please check your email for the OTP.')
        return redirect(url_for('verify2'))

    return render_template('teacher_login.html')


def send_new_course_email(email_content):
    email_address = 'mehulnaik16@gmail.com'
    app_password = 'allletrgoedajdop'

    to_email = 'malathinaik07@gmail.com'

    message = MIMEMultipart()

    message.attach(MIMEText(email_content, 'html'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(email_address, app_password)
    server.sendmail(email_address, to_email, message.as_string())
    server.quit()


@app.route('/send_email', methods=['POST'])
def send_email():
    data = request.get_json()

    email_content = data.get('emailContent')  

    send_new_course_email(email_content)


@app.route('/start-npm', methods=['GET'])
def start_npm():
    try:
        frontend_project_path = r'C:\Users\CHANDU S GOWDA\OneDrive\Desktop\Online'

        os.chdir(frontend_project_path)

        os.system('npm start')

        webbrowser.open('http://localhost:8888/')
    except Exception as e:
        print("Error running npm start:", e)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
