from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from datetime import datetime, date
from werkzeug.security import generate_password_hash
import uuid
from sqlalchemy import Text
from sqlalchemy import Column, Boolean, DateTime, DECIMAL
from flask_login import LoginManager, login_required, current_user
from apscheduler.schedulers.background import BackgroundScheduler
from twilio.rest import Client
from functools import wraps
import os
from werkzeug.utils import secure_filename
from PIL import Image
from flask_login import LoginManager
import re
import requests
from flask_cors import CORS
import boto3
from werkzeug.utils import secure_filename
from botocore.exceptions import NoCredentialsError

from dotenv import load_dotenv
from twilio.rest import Client
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from googleapiclient.discovery import build
from google.oauth2.service_account import Credentials
from dotenv import load_dotenv
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)






# AWS SES Setup
AWS_REGION = 'us-east-1'  # Use your AWS region
SENDER_EMAIL = 'your-ses-verified-email@example.com'  # SES verified email address

# Initialize the SES client
ses_client = boto3.client('ses', region_name=AWS_REGION)


# Initialize AWS clients for SES and SNS
ses_client = boto3.client("ses", region_name="us-west-2")  # Update region if necessary
sns_client = boto3.client("sns", region_name="us-west-2")




# Load environment variables from .env file
load_dotenv()

# Access the SECRET_KEY
SECRET_KEY = os.getenv('SECRET_KEY')



CORS(app)


# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)  # Attach it to the Flask app
login_manager.login_view = 'login'  # Specify the login route name
login_manager.login_message = "Please log in to access this page."  # Optional custom login message
login_manager.login_message_category = "info"  # Optional message category for flash messages


app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["SQLALCHEMY_DATABASE_URI"]  # Use only the environment variable for PostgreSQL URI
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]  # Use only the environment variable for security
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Mail configuration
app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER", "smtp.mailtrap.io")
app.config["MAIL_PORT"] = os.environ.get("MAIL_PORT", 2525)
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME", "your_mailtrap_username")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD", "your_mailtrap_password")
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False


# Add connection pool settings to prevent dropped connections
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,       # automatically reconnect if connection lost
    "pool_recycle": 300,         # refresh connections every 5 mins
    "pool_size": 5,              # maintain up to 5 active connections
    "max_overflow": 10           # allow 10 temporary extra connections
}

# Initialize extensions
mail = Mail(app)

print("Database URI:", app.config["SQLALCHEMY_DATABASE_URI"])

db = SQLAlchemy(app)
migrate = Migrate(app, db)
scheduler = BackgroundScheduler()

# Twilio configuration
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID', 'your_account_sid')
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN', 'your_auth_token')
TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER', 'your_twilio_phone_number')


client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)



# User Model
class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    phone = db.Column(db.String(50))
    email = db.Column(db.String(255), unique=True)
    address = db.Column(db.String(500), nullable=True)
    country = db.Column(db.String(150))
    state = db.Column(db.String(150), nullable=True)
    church_branch = db.Column(db.String(150))
    birthday = db.Column(db.Date, nullable=True)
    password_hash = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=False)
    is_super_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    pledged_amount = db.Column(db.Float, default=0.0)
    pledge_currency = db.Column(db.String(3), default="USD")
    paid_status = db.Column(db.Boolean, default=False)
    medal = db.Column(db.String(100), nullable=True)  
    partner_since = db.Column(db.Integer, nullable=True)  
    donation_date = db.Column(db.Date, nullable=False, default=date.today)
    has_received_onboarding_email = db.Column(db.Boolean, default=False)
    has_received_onboarding_sms = db.Column(db.Boolean, default=False)

    # Relationships
    pledges = db.relationship('Pledge', back_populates='donor', cascade="all, delete-orphan")
    donations = db.relationship("Donation", back_populates="user")

    

    def set_password(self, password):
        """Set the user's password hash."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check if the provided password matches the stored password hash."""
        return check_password_hash(self.password_hash, password)


# Donation model
class Donation(db.Model):
    __tablename__ = 'donations'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(50), default='USD')
    donation_date = db.Column(db.Date, nullable=False, default=date.today)
    payment_type = db.Column(db.String(20), nullable=False, default="full")  # New field for payment type
    receipt_filename = db.Column(db.String(255), nullable=True)  # New field for receipt file name
    amount_paid = db.Column(db.Float, nullable=False, default=0)  # Amount paid so far
    pledged_amount = db.Column(db.Float, nullable=False, default=0)  # Added to store pledged amount
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow) 
    paid_status = db.Column(db.Boolean, default=False)
    reference = db.Column(db.String(100), unique=True, nullable=False)  # Store Paystack reference

    #user = db.relationship('User', backref='pledges')
    #ser = db.relationship("User", backref="donations")
    user = db.relationship("User", back_populates="donations")

    medal = db.Column(db.String(50))  # field to store medal type

    
    
    """
    @property
    def balance(self):
        pledged_amount = self.user.pledged_amount
        return max(0, pledged_amount - self.amount)  # Ensure balance is never below 0
    """



class Pledge(db.Model):
    __tablename__ = 'pledges'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    pledged_amount = db.Column(db.Numeric)  # Ensure this attribute is defined
    pledge_currency = db.Column(db.String)  # Example additional attribute
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    # Relationship to User model
    #user = db.relationship('User', backref='pledges')
    donor = db.relationship('User', back_populates='pledges')  # This should reference 'pledges' in User


class Message(db.Model):
    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)
    sent_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    is_read = db.Column(db.Boolean, default=False)

    



# Twilio credentials from .env
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")


# Environment variables for SendGrid and Twilio
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
FROM_EMAIL = os.getenv("FROM_EMAIL")
RECIPIENT_EMAIL = os.getenv('RECIPIENT_EMAIL')  # Add your recipient email to .env

#print(f"SENDGRID_API_KEY: {SENDGRID_API_KEY}")  # Check if the key is updated

# Ensure environment variables are loaded correctly


# Debugging environment variables
if not SENDGRID_API_KEY or not FROM_EMAIL or not TWILIO_ACCOUNT_SID:
    print("SENDGRID_API_KEY, FROM_EMAIL, or Twilio credentials are missing.")
else:
    print("Environment variables loaded successfully.")


@app.route("/mail_sms", methods=["GET", "POST"])
def mail_sms():
    if request.method == "POST":
        try:
            # Check for email form submission
            if "send_bulk_email" in request.form:
                subject = request.form.get("email_subject", "").strip()
                email_template = request.form.get("email_body", "").strip()

                # Ensure the email template contains placeholders
                if not all(x in email_template for x in ['{name}', '{email}', '{phone}']):
                    flash("The email template must contain {name}, {email}, and {phone}.", "danger")
                    return redirect(url_for("mail_sms"))

                # Send the emails
                send_personalized_emails(subject, email_template)
                flash("Emails sent successfully.", "success")
                return redirect(url_for("delivery_success", delivery_type="Email"))

            # Check for SMS form submission
            if "send_bulk_sms" in request.form:
                sms_template = request.form.get("sms_message", "").strip()

                # Validate SMS template
                if not all(x in sms_template for x in ['{name}', '{email}', '{phone}']):
                    flash("The SMS template must contain {name}, {email}, and {phone}.", "danger")
                    return redirect(url_for("mail_sms"))

                # Send SMS messages
                send_personalized_sms(sms_template)
                flash("SMS sent successfully.", "success")
                return redirect(url_for("delivery_success", delivery_type="SMS"))

            flash("No valid action was selected.", "danger")
            return redirect(url_for("mail_sms"))
        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return redirect(url_for("mail_sms"))

    return render_template("mail_sms.html")

def send_personalized_emails(subject, email_template):
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)

        # Query non-admin users who haven't received the onboarding email
        users_to_email = User.query.filter(
            User.has_received_onboarding_email == False,
            User.is_admin == False  # Exclude admins
        ).all()

        if not users_to_email:
            print("No non-admin users found for email sending.")
            return

        for user in users_to_email:
            try:
                # Personalize email body
                personalized_email_body = email_template.format(
                    name=user.name, phone=user.phone, email=user.email
                )

                # Fix f-string backslash issue
                html_email_body = personalized_email_body.replace('\n', '<br>')

                # Create the email message
                message = Mail(
                    from_email=FROM_EMAIL,
                    to_emails=user.email,
                    subject=subject,
                    plain_text_content=personalized_email_body,
                    html_content=f"<p>{html_email_body}</p>"
                )

                # Send the email
                response = sg.send(message)
                print(f"Email sent to {user.email}: {response.status_code}")

                # Mark email as sent in the database
                if response.status_code == 202:
                    user.has_received_onboarding_email = True
                    db.session.commit()
                else:
                    print(f"Failed to send email to {user.email}: {response.status_code}")

            except Exception as e:
                print(f"Error sending email to {user.email}: {str(e)}")
                continue
    except Exception as e:
        print(f"Error sending emails: {str(e)}")
        raise e



def send_personalized_sms(sms_template):
    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

        # Query non-admin users who haven't received onboarding SMS
        users_to_sms = User.query.filter(
            User.has_received_onboarding_sms == False,
            User.is_admin == False  # Exclude admins
        ).all()

        if not users_to_sms:
            print("No non-admin users found for SMS sending.")
            return

        for user in users_to_sms:
            try:
                # Personalize the SMS body
                personalized_sms_body = sms_template.format(
                    name=user.name, phone=user.phone, email=user.email
                )

                # Send the SMS
                message = client.messages.create(
                    body=personalized_sms_body,
                    from_=TWILIO_PHONE_NUMBER,
                    to=user.phone
                )

                print(f"SMS sent to {user.phone}: {message.status}")

                # Mark SMS as sent in the database
                if message.status in ['queued', 'sent', 'delivered']:
                    user.has_received_onboarding_sms = True
                    db.session.commit()

            except Exception as e:
                print(f"Error sending SMS to {user.phone}: {str(e)}")
                continue
    except Exception as e:
        print(f"Error sending SMS: {str(e)}")
        raise e
    

    
# Success page
@app.route("/delivery_success/<delivery_type>")
def delivery_success(delivery_type):
    return render_template('delivery_success.html', delivery_type=delivery_type)

@app.route('/feedback')
def feedback():
    return render_template('feedback.html')

@app.route('/send-feedback', methods=['POST'])
def send_feedback():
    # Your email handling logic
    name = request.form['name']
    email = request.form['email']
    message = request.form['message']

    # Prepare the email content
    email_message = Mail(
        from_email=email,
        to_emails=RECIPIENT_EMAIL,
        subject=f"Feedback from {name}",
        plain_text_content=f"Name: {name}\nEmail: {email}\nMessage: {message}"
    )

    try:
        # Send email via SendGrid
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(email_message)
        print(f"Response Status Code: {response.status_code}")
        print(f"Response Body: {response.body}")
        flash("Thank you for your feedback! Your message has been sent.", "success")
    except Exception as e:
        print(f"Error: {e}")
        flash(f"An error occurred while sending your feedback: {e}", "danger")

    return redirect(url_for('feedback'))



# Retrieve Paystack secret key from environment
PAYSTACK_SECRET_KEY = os.getenv('PAYSTACK_SECRET_KEY')

@app.route('/verify-payment', methods=['POST'])
def verify_payment():
    data = request.get_json()
    reference = data.get('reference')

    if not reference:
        return jsonify({'status': 'error', 'message': 'No reference provided'}), 400

    # Verify transaction
    url = f"https://api.paystack.co/transaction/verify/{reference}"
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }
    response = requests.get(url, headers=headers)
    result = response.json()

    if result['status']:
        # Payment was successful
        return jsonify({'status': 'success', 'message': 'Payment verified successfully'})
    else:
        # Payment verification failed
        return jsonify({'status': 'error', 'message': 'Payment verification failed'}), 400
    



# Schedule for sending birthday emails
def send_birthday_emails():
    today = datetime.now().date()
    users_with_birthday = User.query.filter(
        db.extract('month', User.birthday) == today.month,
        db.extract('day', User.birthday) == today.day
    ).all()
    for user in users_with_birthday:
        msg = Message(
            "Happy Birthday!",
            sender="noreply@donationtracker.com",
            recipients=[user.email]
        )
        msg.body = f"Dear {user.name},\n\nHappy Birthday! We wish you a wonderful day!\n\nBest regards,\nDonation Tracker Team"
        mail.send(msg)

scheduler.add_job(send_birthday_emails, 'cron', day='*', hour=0)
scheduler.start()




# Decorators to protect routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to be logged in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function



def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash('', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function




# Your registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        phone = request.form.get('phone')
        address = request.form.get('address')
        country = request.form.get('country')  # Country from the dropdown
        state = request.form.get('state')  # State from the dropdown
        manual_country = request.form.get('manual_country')  # Manual country input
        manual_state = request.form.get('manual_state')  # Manual state input

        # Validate required fields
        if not email or not password or not name or not phone or not address or not country or not state:
            flash('Please fill out all required fields.', 'error')
            return render_template('register.html', current_year=datetime.now().year)

        # Use manual country/state if provided; otherwise, fall back to dropdown
        if manual_country:
            country = manual_country
        if manual_state:
            state = manual_state

        # Handle birthday input with optional year
        birthday_str = request.form.get('birthday')  # e.g., '10-10' or '2024-10-10'
        birthday = None
        if birthday_str:
            try:
                # Try parsing in 'YYYY-MM-DD' format
                birthday = datetime.strptime(birthday_str, "%Y-%m-%d").date()
            except ValueError:
                try:
                    # Try parsing in 'DD-MM-YYYY' format
                    birthday = datetime.strptime(birthday_str, "%d-%m-%Y").date()
                except ValueError:
                    flash('Invalid date format for birthday. Please use YYYY-MM-DD or DD-MM-YYYY.', 'error')
                    return render_template('register.html', current_year=datetime.now().year)

        # Get the 'Partner Since' year
        partner_since = request.form.get('partner_since')
        if partner_since:
            try:
                partner_since = int(partner_since)
                if partner_since < 1900 or partner_since > datetime.now().year:
                    raise ValueError
            except ValueError:
                flash('Invalid year for Partner Since. Please provide a valid year.', 'error')
                return render_template('register.html', current_year=datetime.now().year)

        # Check if email is already registered
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email address already registered.', 'error')
            return render_template('register.html', current_year=datetime.now().year)

        # Create a new user
        new_user = User(
            name=name,
            phone=phone,
            email=email,
            address=address,
            country=country,
            state=state,
            church_branch=request.form['church_branch'],  # Ensure this field is also included
            birthday=birthday,
            partner_since=partner_since,  # Store the Partner Since year
            is_admin=False,
            is_super_admin=False
        )
        new_user.set_password(password)  # Set hashed password

        try:
            # Save user to the database
            db.session.add(new_user)
            db.session.commit()

            # Send confirmation email
            message = Mail(
                from_email='martinagoha7@gmail.com',  # Replace with your verified SendGrid sender email
                to_emails=email,
                subject='Welcome to Our Platform!',
                html_content=f"""
                   <h3>Welcome to FaithLedger, {name}! 🙏</h3>
                    <p>Thank you for joining FaithLedger. Your account has been successfully created. 🎉</p>
                    <p>You can now log in using your registered email and password to access your dashboard. 🔑</p>
                    <p>For any support, reach us at <a href="mailto:support@faithledger.org">support@faithledger.org</a>. 📩</p>
                    <p>Blessings,<br>The FaithLedger Team</p>

                """
            )

            sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))  # Set your SendGrid API key in the environment
            response = sg.send(message)
            print(f"Email sent! Status Code: {response.status_code}")

        except IntegrityError:
            db.session.rollback()
            flash('An account with this email or phone number already exists.', 'error')
            return render_template('register.html', current_year=datetime.now().year)

        except Exception as e:
            print(f"Error sending email: {e}")
            flash('Registration successful, but we couldn\'t send a confirmation email.', 'warning')

        # Render a success page and redirect to login
        flash('Registration successful! A confirmation email has been sent.', 'success')
        return render_template('success2.html')  # Immediately show success template

    # Render the registration form
    return render_template('register.html', current_year=datetime.now().year)



@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)  # Assuming `User` is your user table





# Home route
@app.route("/")
def index():
    return render_template("index.html")

 # Renders the index page dynamically


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # Clear previous flash messages when the login page is loaded
        session.pop('_flashes', None)

    if request.method == 'POST':
        login_input = request.form['email']  # We'll use 'email' form field for both email and phone number input

        # Check if the input is an email or phone number
        if re.match(r"[^@]+@[^@]+\.[^@]+", login_input):  # Email pattern check
            user = User.query.filter_by(email=login_input).first()
        else:  # Assume input is a phone number
            user = User.query.filter_by(phone=login_input).first()  # Assuming you have a phone_number column in the User model

        if user and user.check_password(request.form['password']):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            session['is_super_admin'] = user.is_super_admin

            flash(f'Welcome, {user.name}!', 'success')

            # Redirect admins to the admin dashboard
            if user.is_admin or user.is_super_admin:
                return redirect(url_for('admin_dashboard'))

            # Redirect regular users to home2.html
            return redirect(url_for('home2'))
        else:
            flash('Invalid email/phone number or password.', 'danger')

    return render_template('login.html')





@app.route('/home2')
def home2():
    # Check if the user is logged in
    if 'user_id' not in session:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))

    # Retrieve user information
    user = User.query.get(session['user_id'])

    # Check if the user exists
    if not user:
        flash('User not found', 'error')  # Show a user-friendly error message
        return redirect(url_for('login'))  # Redirect to login or another page

    # Render the template with the user data
    return render_template(
        'home2.html',
 user=user
)

# AWS S3 Configuration
app.config['S3_BUCKET'] = 'dcglobal-uploads'
app.config['S3_ACCESS_KEY'] = os.getenv('AWS_ACCESS_KEY_ID')
app.config['S3_SECRET_KEY'] = os.getenv('AWS_SECRET_ACCESS_KEY')
app.config['S3_REGION'] = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')

# Initialize S3 client once
s3_client = boto3.client(
    's3',
    aws_access_key_id=app.config['S3_ACCESS_KEY'],
    aws_secret_access_key=app.config['S3_SECRET_KEY'],
    region_name=app.config['S3_REGION']
)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}

# Initialize mail
mail = Mail(app)

# Check allowed file type
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Compress image if needed
def compress_image(filepath):
    with Image.open(filepath) as img:
        img.save(filepath, optimize=True, quality=85)

# Generate pre-signed S3 URL (for private bucket)
def get_s3_file_url(filename, expiration=3600):
    try:
        url = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': app.config['S3_BUCKET'], 'Key': filename},
            ExpiresIn=expiration
        )
        return url
    except Exception as e:
        app.logger.error(f"Error generating pre-signed URL: {e}")
        return None

# Upload route
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash("No file selected for upload", "danger")
        return redirect(request.referrer)

    file = request.files['file']
    if file.filename == '':
        flash("No selected file", "danger")
        return redirect(request.referrer)

    if file and allowed_file(file.filename):
        # Generate unique filename
        filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
        try:
            # Upload to S3
            s3_client.upload_fileobj(
                file,
                app.config['S3_BUCKET'],
                filename,
            )

            # Save filename to donation record
            donation_id = request.form.get('donation_id')
            donation = Donation.query.get(donation_id)
            if donation:
                donation.receipt_filename = filename
                db.session.commit()

            flash("File uploaded successfully!", "success")
            return redirect(url_for('receipts_overview'))

        except Exception as e:
            app.logger.error(f"S3 upload failed: {e}")
            flash("Failed to upload file. Please try again.", "danger")
            return redirect(request.referrer)

    flash("Invalid file type", "danger")
    return redirect(request.referrer)

# Delete file from S3
def delete_file_from_s3(filename):
    try:
        s3_client.delete_object(Bucket=app.config['S3_BUCKET'], Key=filename)
        app.logger.info(f"File {filename} deleted from S3.")
    except NoCredentialsError:
        app.logger.error("AWS credentials not found.")
    except Exception as e:
        app.logger.error(f"Error deleting file {filename} from S3: {e}")



def get_s3_presigned_url(filename, expiration=3600):
    try:
        url = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': app.config['S3_BUCKET'], 'Key': filename},
            ExpiresIn=expiration
        )
        return url
    except Exception as e:
        app.logger.error(f"Error generating presigned URL: {e}")
        return None


# Delete receipt route
@app.route('/delete_receipt/<filename>', methods=['POST'])
def delete_receipt_by_filename(filename):
    delete_file_from_s3(filename)

    donation = Donation.query.filter_by(receipt_filename=filename).first()
    if donation:
        donation.receipt_filename = None
        db.session.commit()

    flash("Receipt deleted successfully.", "success")
    return redirect(url_for('receipts_overview'))

# Receipts overview
@app.route('/receipts-overview')
def receipts_overview():
    return render_template('admin_uploaded_receipts.html')

# View receipt
@app.route('/view_receipt/<filename>')
def view_receipt(filename):
    donation = Donation.query.filter_by(receipt_filename=filename).first_or_404()
    currency = getattr(donation, 'currency', 'USD')
    file_url = get_s3_file_url(donation.receipt_filename)
    return render_template('view_receipt.html', donation=donation, currency=currency, file_url=file_url)

# Admin uploaded receipts
@app.route("/admin_uploaded_receipts", methods=["GET", "POST"])
@admin_required
def admin_uploaded_receipts():
    search_term = request.args.get("search_term", "").lower()

    receipts = (
        db.session.query(
            Donation.receipt_filename,
            User.name,
            User.country,
            User.state,
            User.church_branch
        )
        .join(User, Donation.user_id == User.id)
        .filter(Donation.receipt_filename.isnot(None))
    )

    if search_term:
        receipts = receipts.filter(
            db.or_(
                User.name.ilike(f"%{search_term}%"),
                User.country.ilike(f"%{search_term}%"),
                User.state.ilike(f"%{search_term}%"),
                User.church_branch.ilike(f"%{search_term}%")
            )
        )

    receipts = receipts.all()

    uploaded_receipts = [
        {
            "filename": receipt.receipt_filename,
            "user": receipt.name,
            "country": receipt.country,
            "state": receipt.state,
            "church_branch": receipt.church_branch,
            "file_url": get_s3_file_url(receipt.receipt_filename)
        }
        for receipt in receipts
    ]

    return render_template('admin_uploaded_receipts.html', files=uploaded_receipts, search_term=search_term)



@app.route('/s3-test')
def s3_test():
    import boto3
    import os
    s3 = boto3.client(
        's3',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name=os.getenv('AWS_DEFAULT_REGION')
    )
    try:
        buckets = [b['Name'] for b in s3.list_buckets()['Buckets']]
        return f"S3 Buckets: {buckets}"
    except Exception as e:
        return f"Error: {e}"


"""
@app.route('/view_receipt/<int:receipt_id>')
def view_receipt(receipt_id):
    # Fetch a single receipt by its ID
    receipt = Donation.query.get_or_404(receipt_id)  # Assuming Donation has all receipt data
    
    # Ensure the `currency` is part of the receipt object
    currency = receipt.currency if hasattr(receipt, 'currency') else 'USD'  # Default to USD if currency is missing
    
    # Render the receipt details page
    return render_template('view_receipt.html', receipt=receipt, currency=currency)
"""



        
@app.route('/view_my_donations')
def view_my_donations():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    
    # Get the user object
    user = User.query.get(user_id)  # Fetch user by user_id

    if not user:
        return "User not found", 404
    
    # Get all donations made by this user, sorted by timestamp
    donations = Donation.query.filter_by(user_id=user_id).order_by(Donation.timestamp.asc()).all()

    if not donations:
        return render_template('view_my_donations.html', donation_details=[], message="No donations found.")

    donation_details = []
    pledged_amount = user.pledged_amount if user.pledged_amount is not None else 0

    for donation in donations:
        # Amount paid for this particular donation
        amount = donation.amount

        # Check if the donation's payment_type is "full_payment"
        if (isinstance(donation.payment_type, str) and donation.payment_type.lower() == "full_payment"):
            balance = 0  # Automatically set balance to zero if payment_type is "full_payment"
        else:
            # Calculate the balance for this donation
            balance = max(pledged_amount - amount, 0)  # Ensure balance is not negative

        # Debugging output for checking values
        print(f"Donation ID: {donation.id} | Payment Type: {donation.payment_type} | Pledged Amount: {pledged_amount} | Amount Paid: {amount} | Calculated Balance: {balance} | Timestamp: {donation.timestamp}")

        # Timestamp for this donation
        timestamp = donation.timestamp  

        donation_details.append({
            'donation': donation,
            'balance': balance,
            'amount': amount,
            'timestamp': timestamp
        })

    return render_template('view_my_donations.html', donation_details=donation_details, message=None)



#Partner delete donation

@app.route("/delete_user_donation/<int:donation_id>", methods=["POST"])
def delete_user_donation(donation_id):
    if 'user_id' not in session:
        flash("You need to log in to perform this action.", "danger")
        return redirect(url_for("login"))
    
    user_id = session['user_id']
    donation = Donation.query.filter_by(id=donation_id, user_id=user_id).first()
    
    if not donation:
        flash("Donation not found or you do not have permission to delete it.", "danger")
        return redirect(url_for("view_my_donations"))

    try:
        db.session.delete(donation)
        db.session.commit()
        flash("Donation deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting donation: {e}")
        flash("An error occurred while deleting the donation.", "danger")
    
    return redirect(url_for("view_my_donations"))




"""
@app.route('/view_my_donations')
def view_my_donations():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    donations = Donation.query.filter_by(user_id=user_id).all()
    user = User.query.get(user_id)

    if not user:
        return "User not found", 404

    donation_details = []
    for donation in donations:
        pledged_amount = user.pledged_amount
        balance = max(0, pledged_amount - donation.amount)  # Ensure balance is never below 0
        donation_details.append({
            'donation': donation,
            'balance': balance,
            'amount': donation.amount
        })

    return render_template('view_my_donations.html', donation_details=donation_details
"""
@app.route("/donate", methods=["GET", "POST"])
def donate():
    user = None
    if "user_id" in session:
        user = get_current_user()  # Retrieve current logged-in user
        app.logger.debug(f"User object: {user}")
        if user:
            db.session.refresh(user)  # Ensure latest data from DB

    if request.method == "POST":
        user_id = session.get("user_id")
        payment_type = request.form.get("payment_type")

        # Offline donation fields
        amount = request.form.get("amount")
        currency = request.form.get("currency")
        donation_date = request.form.get("date_donated")
        receipt = request.files.get("receipt")

        # Validate required fields
        if not all([amount, payment_type, currency, donation_date]):
            flash("Please fill in all required fields.", "danger")
            return redirect(url_for("donate"))

        # Validate amount
        try:
            amount = float(amount)
            if amount <= 0:
                flash("Donation amount must be greater than zero.", "danger")
                return redirect(url_for("donate"))
        except (ValueError, TypeError):
            flash("Invalid amount format.", "danger")
            return redirect(url_for("donate"))

        # Validate donation date
        try:
            donation_date = datetime.strptime(donation_date, "%Y-%m-%d").date()
        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DD.", "danger")
            return redirect(url_for("donate"))

        # Handle receipt upload to S3
        receipt_filename = None
        if receipt and allowed_file(receipt.filename):
            receipt_filename = secure_filename(receipt.filename)
            s3_key = f"receipts/{user_id}/{receipt_filename}"
            try:
                s3_client.upload_fileobj(
                    receipt,
                    app.config['S3_BUCKET'],
                    s3_key  # ✅ Removed ACL
                )
            except Exception as e:
                app.logger.error(f"S3 Upload Error: {e}")
                flash("Error uploading receipt. Please try again.", "danger")
                return redirect(url_for("donate"))
        elif receipt:
            flash("Invalid file type. Allowed types: PNG, JPG, JPEG, GIF, PDF.", "danger")
            return redirect(url_for("donate"))

        # Generate unique reference
        def generate_unique_reference():
            while True:
                reference_code = str(uuid.uuid4())[:10]
                existing = Donation.query.filter_by(reference=reference_code).first()
                if not existing:
                    return reference_code

        reference_code = generate_unique_reference()

        # Create donation
        donation = Donation(
            user_id=user_id,
            amount=amount,
            currency=currency,
            donation_date=donation_date,
            payment_type=payment_type,
            receipt_filename=receipt_filename,
            reference=reference_code
        )

        try:
            db.session.add(donation)
            db.session.commit()

            # Update pledge balance if exists
            pledge = Pledge.query.filter_by(user_id=user_id).first()
            if pledge:
                pledged_amount = pledge.amount
                pledge.balance = max(0, pledged_amount - amount)
                db.session.commit()

            flash(f"Thank you for your {payment_type} donation!", "success")
            app.logger.info(f"Donation saved: {donation.amount}, User ID: {user_id}, Reference: {reference_code}")
            return redirect(url_for("donation_success"))

        except IntegrityError:
            db.session.rollback()
            app.logger.error("Database Integrity Error: Possible duplicate reference.")
            flash("There was an error processing your donation. Please try again.", "danger")
            return redirect(url_for("donate"))

        except Exception as e:
            db.session.rollback()
            traceback.print_exc()
            app.logger.error(f"Error saving donation: {e}")
            flash("There was an error processing your donation. Please try again.", "danger")
            return redirect(url_for("donate"))

    # GET request
    pledges = db.session.query(Pledge, User).join(User, Pledge.user_id == User.id).all()
    return render_template("donate.html", user=user, pledges=pledges, donation_date=date.today())

# Helper to generate a pre-signed URL for private S3 files
def get_s3_presigned_url(filename, expiration=3600):
    s3_key = f"receipts/{session.get('user_id')}/{filename}"
    try:
        url = s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": app.config['S3_BUCKET'], "Key": s3_key},
            ExpiresIn=expiration
        )
        return url
    except Exception as e:
        app.logger.error(f"Error generating presigned URL: {e}")
        return None



@app.route('/update_payment', methods=['POST'])
def update_payment():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    donation_id = request.form.get('donation_id')
    donation = Donation.query.get(donation_id)

    if not donation:
        return "Donation not found", 404

    # Get the new payment amount (this will update the 'amount' field)
    new_payment = float(request.form.get('new_payment', 0))

    # Update the donation's amount (not amount_paid)
    donation.amount += new_payment  # Add to the 'amount' field instead of subtracting

    db.session.commit()

    return redirect(url_for('view_my_donations'))



@app.route('/recent_donations', methods=['GET', 'POST'])
def recent_donations():
    # Only clear session keys unrelated to authentication
    session.pop('some_other_key', None)  # Example of clearing unrelated session data
    # Avoid clearing user_id, is_admin, or is_super_admin here

    search_term = request.form.get('search_term', '').strip()  # Get search term from form, with trimming

    # Build the base query for donations
    query = Donation.query

    if search_term:
        # Search by User fields (name, country, state, church_branch)
        query = query.join(User, User.id == Donation.user_id).filter(
            (User.name.ilike(f"%{search_term}%")) |
            (User.country.ilike(f"%{search_term}%")) |
            (User.state.ilike(f"%{search_term}%")) |
            (User.church_branch.ilike(f"%{search_term}%")) |
            (Donation.payment_type.ilike(f"%{search_term}%"))
        )

    # Fetch donations, ordered by donation date
    recent_donations = query.order_by(Donation.donation_date.desc()).all()

    return render_template('recent_donations.html', 
                           recent_donations=recent_donations, 
                           search_term=search_term)



def get_current_user():
    user_id = session.get("user_id")
    return User.query.get(user_id) if user_id else None  # Adjust according to your ORM




# Donation success route
@app.route("/donation_success")
@login_required
def donation_success():
    return render_template("donation_success.html")




# Function to send email via SendGrid
def send_registration_email(email, name, phone):
    message = Mail(
        from_email='partnership@dominioncityglobal.org',  # Replace with your SendGrid-verified sender email
        to_emails=email,
        subject='Admin Registration Successful',
        html_content=f"""
        <p>Dear {name},</p>
        <p>Congratulations! You have been successfully registered as an admin.</p>
        <p>Your login details are as follows:</p>
        <ul>
            <li><strong>Username:</strong> {phone} or {email}</li>
            <li><strong>Password:</strong> {phone} or {email}</li>
        </ul>
        <p>You can change your password after logging in for the first time.</p>
        <p>Best regards,<br>The Team</p>
        """
    )
    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        response = sg.send(message)
        if response.status_code == 202:
            print('Email sent successfully!')
        else:
            print(f'Failed to send email: {response.status_code}')
    except Exception as e:
        print(f'Error sending email: {e}')


@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        phone = request.form.get('phone')
        address = request.form.get('address')
        country = request.form.get('country')
        state = request.form.get('state')  # This is the selected state
        manual_country = request.form.get('manual_country')  # Manual country input
        manual_state = request.form.get('manual_state')  # Manual state input
        church_branch = request.form.get('church_branch')

        # Use manual country/state if provided
        if manual_country:
            country = manual_country
        if manual_state:
            state = manual_state

        # Ensure email is unique
        existing_admin = User.query.filter_by(email=email).first()
        if existing_admin:
            flash('Email address already registered.', 'error')
            return render_template('admin_register.html')

        # Create new admin user
        new_admin = User(
            name=name,
            phone=phone,
            email=email,
            address=address,
            country=country,
            state=state,
            church_branch=church_branch,
            is_admin=True,        # Admin user
            is_super_admin=False  # Not a super admin
        )
        new_admin.set_password(password)

        # Commit to the database
        db.session.add(new_admin)
        db.session.commit()

        # Send email via SendGrid
        send_registration_email(email, name, phone)

        flash('Admin registration successful! You can now log in.', 'success')
        return redirect(url_for('admin_login'))  # Adjust the redirect as necessary

    return render_template('admin_register.html')  # Render the registration form template


# Admin login
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Retrieve the admin record
        admin = User.query.filter_by(email=email, is_admin=True).first()

        if admin and admin.check_password(password):
            session['user_id'] = admin.id
            session['is_admin'] = admin.is_admin
            session['is_super_admin'] = admin.is_super_admin

            flash(f'Welcome, {admin.name}!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('admin_login.html')




# Make sure you have this set up for static uploads
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route("/admin_dashboard", methods=["GET", "POST"])
@admin_required
def admin_dashboard():
    # Initialize search filter as empty
    search_term = None
    filtered_users = User.query.order_by(User.name).all()  # Default query to fetch all users

    if request.method == "POST":
        try:
            # Retrieve search parameter
            search_term = request.form.get('search_term')

            # Start with the base query on the User model
            query = User.query.order_by(User.name)

            # Apply search filter if provided (filtering User fields)
            if search_term:
                query = query.filter(
                    (User.country.ilike(f"%{search_term}%")) |
                    (User.state.ilike(f"%{search_term}%")) |
                    (User.church_branch.ilike(f"%{search_term}%")) |
                    (User.name.ilike(f"%{search_term}%"))
                )
            
            # Fetch the filtered users
            filtered_users = query.all()

        except ValueError as e:
            flash("Invalid search input.", "error")
    
    # Fetch all users (already filtered based on search, if any)
    users = filtered_users

    # List files in the upload folder
    uploaded_files = os.listdir(app.config['UPLOAD_FOLDER'])

    return render_template("admin_dashboard.html", 
                           users=users, 
                           search_term=search_term,
                           files=uploaded_files)


"""
#SENDING NOTIFICATIONS(MAIL AND SMS USING AWS)
@app.route("/mail_sms", methods=["GET", "POST"])
def mail_sms():
    if request.method == "POST":
        try:
            # Handle bulk SMS sending
            if "send_bulk_sms" in request.form:
                message = request.form["sms_message"]
                phone_numbers = request.form["phone_numbers"].split(",")  # Split by commas to get a list
                phone_numbers = [num.strip() for num in phone_numbers]  # Remove any extra whitespace
                send_bulk_sms(message, phone_numbers)
                flash("Bulk SMS sent successfully!", "success")

            # Handle bulk email sending
            elif "send_bulk_email" in request.form:
                subject = request.form["email_subject"]
                body = request.form["email_body"]
                recipients = request.form["recipients"].split(",")  # Split by commas to get a list
                recipients = [email.strip() for email in recipients]  # Remove any extra whitespace
                send_bulk_email(subject, body, recipients)
                flash("Bulk email sent successfully!", "success")
                
            return redirect(url_for('admin_dashboard'))
        
        except Exception as e:
            flash("An error occurred: " + str(e), "danger")
    
    return render_template("mail_sms.html")


# Function to send bulk email using AWS SES
def send_bulk_email(subject, body, recipients):
    try:
        response = ses_client.send_email(
            Source='your-email@example.com',  # Replace with your verified SES email
            Destination={'ToAddresses': recipients},
            Message={
                'Subject': {'Data': subject},
                'Body': {'Text': {'Data': body}}
            }
        )
        print("Email sent! Message ID:", response['MessageId'])
    except (BotoCoreError, ClientError) as error:
        print(f"An error occurred with SES: {error}")


"""


def validate_phone_number(phone_number):
    # Regex pattern for validating E.164 phone numbers
    pattern = r'^\+[1-9]{1}[0-9]{1,14}$'
    if re.match(pattern, phone_number):
        return True
    else:
        return False




# API endpoint to fetch user details by ID
@app.route('/user/<int:user_id>', methods=['GET'])
def get_user(user_id):
    # Fetch user details using SQLAlchemy
    user = User.query.get(user_id)
    
    if user is None:
        return jsonify({'error': 'User not found'}), 404
    
    # Fetch donation history for the user
    donations = Donation.query.filter_by(user_id=user_id).all()
    
    # Prepare donations list
    donation_history = [{'amount': donation.amount, 'currency': donation.currency} for donation in donations]
    
    return jsonify({
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'address': user.address,
        'country': user.country,
        'state': user.state,
        'church_branch': user.church_branch,
        'birthday': user.birthday,
        'role': 'Admin' if user.is_admin else 'User',
        'phone': user.phone,
        'donation_history': donation_history,  # List of donations for the user
        'is_active': user.is_active,
        'created_at': user.created_at,
        'updated_at': user.updated_at
    }), 200



# Route to delete a user
@app.route("/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    try:
        # Delete the user; associated pledges will be deleted automatically
        db.session.delete(user)
        db.session.commit()
        flash("User deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting user: {e}")
        flash("An error occurred while deleting the user.", "danger")
    return redirect(url_for("admin_dashboard"))




@app.route("/delete_donation/<int:donation_id>", methods=["POST"])
@admin_required
def delete_donation(donation_id):
    donation = Donation.query.get_or_404(donation_id)  # Fetch the donation or 404 if not found
    try:
        # Attempt to delete the donation from the database
        db.session.delete(donation)
        db.session.commit()
        flash("Donation deleted successfully.", "success")  # Success flash message
    except Exception as e:
        # Handle any errors and log them
        db.session.rollback()
        app.logger.error(f"Error deleting donation: {e}")
        flash("An error occurred while deleting the donation.", "danger")  # Error flash message

    # Redirect to the admin dashboard after action is completed
    return redirect(url_for("recent_donations"))



@app.route('/add_pledge', methods=['GET', 'POST'])
def add_pledge():
    if request.method == 'POST':
        # Handling form submission
        if request.form:
            user_id = request.form['user_id']  # Get the user ID from the form
            pledged_amount = request.form['pledged_amount']
            pledge_currency = request.form['currency']
            medal = request.form.get('medal')  # Get the selected medal from the form
            donation_date_str = request.form['donation_date']  # Get the donation date from the form

            # Convert the donation_date to a datetime object
            try:
                donation_date = datetime.strptime(donation_date_str, '%Y-%m-%d')
            except ValueError:
                flash('Invalid donation date. Please provide a valid date.', 'danger')
                return redirect(url_for('add_pledge', user_id=user_id))  # Redirect to the form

            # Remove commas from pledged amount before converting to float
            pledged_amount = pledged_amount.replace(',', '')

            try:
                # Convert pledged amount to float
                pledged_amount = float(pledged_amount)
            except ValueError:
                flash('Invalid pledged amount. Please enter a valid number.', 'danger')
                return redirect(url_for('add_pledge', user_id=user_id))  # Redirect to the form

            # Fetch the user from the User table
            user = User.query.get(user_id)

            if user:
                # Update the pledged amount, currency, medal, and donation date in the User table
                user.pledged_amount = pledged_amount
                user.pledge_currency = pledge_currency
                user.medal = medal  # Save the selected medal type
                user.donation_date = donation_date  # Save the donation date

                # Commit the changes to the database
                db.session.commit()

                # Check the admin status of the logged-in user and redirect accordingly
                logged_in_user = User.query.get(session.get('user_id'))  # Assuming user_id is stored in the session
                if logged_in_user and (logged_in_user.is_admin or logged_in_user.is_super_admin):
                    flash('Pledge added successfully! You will be redirected to the admin dashboard.', 'success')
                    return render_template('success.html', next_url=url_for('admin_dashboard'))
                else:
                    flash('Pledge added successfully! You will be redirected to the home page.', 'success')
                    return render_template('success.html', next_url=url_for('home2'))
            else:
                flash('User not found!', 'danger')
                return redirect(url_for('add_pledge', user_id=user_id))  # Redirect in case user not found

    # Add the user_id to the template when rendering the page
    user_id = request.args.get('user_id')
    return render_template('add_pledge.html', user_id=user_id)



def get_user_by_id(user_id):
    return User.query.get(user_id)  



#Route to Confirm Partners' Pledges and reset to zero after payment is completed in full
@app.route('/update_pledge/<int:user_id>', methods=['GET', 'POST'])
def update_pledge(user_id):
    if request.method == 'POST':
        # Fetch the user's record from the User table
        user = User.query.filter_by(id=user_id).first()

        if user:
            print(f"Before update - User ID {user_id} - Pledged Amount: {user.pledged_amount}")  # Debugging line

            # Reset pledged amount to zero
            user.pledged_amount = 0

            try:
                db.session.commit()  # Commit the change to the database
                print(f"After update - User ID {user_id} - Pledged Amount: {user.pledged_amount}")  # Debugging line
            except Exception as e:
                print(f"Error committing to database: {e}")
                db.session.rollback()  # Rollback in case of an error

            # Verify if the change was successful
            updated_user = User.query.filter_by(id=user_id).first()
            if updated_user and updated_user.pledged_amount == 0:
                flash(f'Pledge for user {user_id} has been reset to zero!')
            else:
                flash('Error: Unable to reset the pledge amount.', 'error')

        else:
            flash(f'No user found with ID {user_id}.', 'error')
            print(f"No user found with ID {user_id}")  # Debugging line

        # Redirect to the admin dashboard to reflect the updated pledge
        return redirect(url_for('admin_dashboard')) 


    # For GET requests, display the update page with current pledge information
    user = User.query.filter_by(id=user_id).first()

    if user is None:
        print(f"No user found with ID {user_id}.")  # Debugging line
    else:
        print(f"GET request - Current pledge for user {user_id}: {user.pledged_amount}")  # Debugging line
        
    return render_template('update_pledge.html', user=user)




def get_current_pledge(user_id):
    return Pledge.query.filter_by(user_id=user_id).first()




@app.route('/view_partners_pledges', methods=['GET', 'POST'])
@login_required  
@admin_required 
def view_partners_pledges():
    search_query = request.form.get('search_query') if request.method == 'POST' else None

    # Constructing the filter condition based on search query
    if search_query:
        users = User.query.filter(
            User.is_admin == False, 
            (User.name.ilike(f"%{search_query}%") | 
             User.state.ilike(f"%{search_query}%") | 
             User.country.ilike(f"%{search_query}%") | 
             User.church_branch.ilike(f"%{search_query}%"))
        ).all()
    else:
        users = User.query.filter(User.is_admin == False).all()  # Fetch all non-admin users if no search query

    return render_template('view_partners_pledges.html', users=users, search_query=search_query)


@app.route('/view_partners_details', methods=['GET', 'POST'])
@login_required  # Ensure the user is logged in
@admin_required  # Ensure the user is an admin
def view_partners_details():
    # Retrieve the search_query from the form if it's a POST request
    search_query = request.form.get('search_query') if request.method == 'POST' else None

    # Start the query by filtering out admins
    query = User.query.filter(User.is_admin == False)

    # Apply filters based on the search query (matching in name, country, state, or local church)
    if search_query:
        query = query.filter(
            (User.name.ilike(f"%{search_query}%")) |
            (User.country.ilike(f"%{search_query}%")) |
            (User.state.ilike(f"%{search_query}%")) |
            (User.church_branch.ilike(f"%{search_query}%"))
        )

    # Execute the query
    users = query.all()

    return render_template('view_partners_details.html', 
                           users=users, 
                           search_query=search_query)





#View Admin Details
@app.route('/view_admin_details', methods=['GET', 'POST'])
@login_required  
@admin_required
def view_admin_details():
    # Retrieve the search_country from the form if it's a POST request
    search_country = request.form.get('search_country') if request.method == 'POST' else None

    # Filter out non-admins and apply country filter if search_country is provided
    if search_country:
        admins = User.query.filter(User.is_admin == True, User.country.ilike(f"%{search_country}%")).all()
    else:
        admins = User.query.filter(User.is_admin == True).all()  # Fetch all admin users

    return render_template('view_admin_details.html', admins=admins, search_country=search_country)



@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403 


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        email_or_phone = request.form.get('email_or_phone')
        new_password = request.form.get('new_password')

        # Validate email or phone (check if it exists in the database)
        user = User.query.filter((User.email == email_or_phone) | (User.phone == email_or_phone)).first()

        if not user:
            flash('Invalid email or phone number', 'error')
            return redirect(url_for('change_password'))

        # Hash the new password
        hashed_password = generate_password_hash(new_password)

        # Update the password in the database
        try:
            user.password_hash = hashed_password
            db.session.commit()
            flash('Password successfully changed', 'success')
            return redirect(url_for('change_password'))  # Optionally redirect back to the form
        except Exception as e:
            db.session.rollback()
            flash('Error updating password. Please try again.', 'error')
            return redirect(url_for('change_password'))

    return render_template('change_password.html')  # Render the password change form







@app.route('/contact')
def contact():
    return render_template('contact.html')  # Renders the contact page



    
@app.route("/select_payment_options", methods=["GET"])
@login_required
def select_payment_options():
    return render_template("select_payment_options.html")





# Twilio API setup
TWILIO_SID = os.getenv('TWILIO_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')

# Function to send email
def send_welcome_email(email, name, phone=None):
    try:
        message = Mail(
            from_email='partnership@dominioncityglobal.org',
            to_emails=email,
            subject='Welcome to DC Global Partnership Mission!',
            html_content=f"""
                <h1>Welcome to DC Global Partnership Mission, {name}! 🎉</h1>
                <p>We are excited to inform you that you have been successfully onboarded to our platform. 🙌</p>

                <p>You were onboarded directly by the admin after filling out the form received from the church. Kindly use the login details below to access your portal: 🔑</p>
                <ul>
                    <li><strong>Username:</strong> {phone} or {email}</li>
                    <li><strong>Password:</strong> {phone} or {email}</li>
                </ul>

                <p>To proceed, please visit the following link to access your portal: 🌐</p>
                <p><a href="http://www.dcglobal.org">www.dcglobal.org</a></p>

                <p>If you have any inquiries or need assistance, please feel free to reach out to us at <a href="mailto:support@example.com">support@example.com</a>. 📩</p>

                <p>Thank you for being part of our community, and we look forward to your engagement. 🌟</p>

                <p>Best regards,<br>The DC Global Partnership Mission Team</p>

            """
        )
        sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
        response = sg.send(message)
        print(f"Email sent to {email}. Status Code: {response.status_code}")
    except Exception as e:
        print(f"Error sending email: {e}")
        flash('Registration successful, but we couldn\'t send a confirmation email.', 'warning')


# Function to send SMS
def send_welcome_sms(phone, name):
    try:
        client = Client(TWILIO_SID, TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            body=f"Hello {name}, welcome to DC Global Partnership Mission! You have been successfully onboarded.",
            from_=TWILIO_PHONE_NUMBER,
            to=phone
        )
        print(f"SMS sent to {phone}. SID: {message.sid}")
    except Exception as e:
        print(f"Error sending SMS: {e}")
        flash('Registration successful, but we couldn\'t send a confirmation SMS.', 'warning')


# Load environment variables
SERVICE_ACCOUNT_FILE = os.getenv('GOOGLE_SHEET_API_KEY_PATH')
SERVICE_ACCOUNT_FILE = os.getenv('SERVICE_ACCOUNT_JSON')

SPREADSHEET_ID = os.getenv('SPREADSHEET_ID')

# Define SCOPES (Google Sheets API Scope)
SCOPES = ['https://www.googleapis.com/auth/spreadsheets']

@app.route('/sync_with_google_sheets', methods=['POST'])
def sync_with_google_sheets():
    try:
        # Authenticate using Google service account
        creds = Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES)
        service = build('sheets', 'v4', credentials=creds)

        # === Step 1: Import Data from Google Sheets ===
        sheet_range = 'Registration!A1:J'  # Adjust range to include all columns
        result = service.spreadsheets().values().get(
            spreadsheetId=SPREADSHEET_ID,
            range=sheet_range
        ).execute()
        rows = result.get('values', [])

        if not rows or len(rows) <= 1:  # First row is header
            flash('No data found in the Google Sheet or only header row present.', 'error')
            return redirect(url_for('view_partners_pledges'))

        # Process rows (skipping the header)
        for i, row in enumerate(rows[1:], start=2):  # Start from row 2 for better debugging
            name = row[0] if len(row) > 0 else None
            phone = row[1] if len(row) > 1 else None
            email = row[2] if len(row) > 2 else None
            address = row[3] if len(row) > 3 else None
            country = row[4] if len(row) > 4 else None
            state = row[5] if len(row) > 5 else None
            church_branch = row[6] if len(row) > 6 else None
            birthday_str = row[7] if len(row) > 7 else None
            pledged_amount = row[8] if len(row) > 8 else None

            # Process pledge_currency directly
            pledge_currency = row[9].strip().upper() if len(row) > 9 else None

            # Parse birthday
            birthday = None
            if birthday_str:
                try:
                    birthday = datetime.strptime(birthday_str, "%Y-%m-%d").date()
                except ValueError:
                    birthday = None

            # Check if user already exists by email or phone (handling None gracefully)
            if email and phone:
                existing_user = User.query.filter((User.email == email) | (User.phone == phone)).first()
            elif email:
                existing_user = User.query.filter_by(email=email).first()
            elif phone:
                existing_user = User.query.filter_by(phone=phone).first()
            else:
                existing_user = None  # Skip check if both email and phone are missing

            if existing_user:
                print(f"Row {i}: User with email {email} or phone {phone} already exists. Skipping.")
                continue

            # Create new user if they don't already exist
            new_user = User(
                name=name,
                phone=phone,
                email=email,
                address=address,
                country=country,
                state=state,
                church_branch=church_branch,
                birthday=birthday,
                pledged_amount=pledged_amount,
                pledge_currency=pledge_currency,
                is_admin=False,
                is_super_admin=False,
                is_active=True,
                created_at=datetime.now(),
                updated_at=datetime.now(),
                password_hash="hashed_password_placeholder",  # Replace with actual hashed password if needed
                has_received_onboarding_email=False,
                has_received_onboarding_sms=False
            )
            new_user.set_password(phone or email)  # Use phone or email for password (hashed)
            db.session.add(new_user)

            # Send email and SMS after user creation
            if email:
                send_welcome_email(email, name, phone)
            if phone:
                send_welcome_sms(phone, name)

        db.session.commit()  # Commit all changes at once for efficiency
        flash('Data synchronization with Google Sheets completed successfully.', 'success')
        return redirect(url_for('view_partners_pledges'))

    except Exception as e:
        flash(f"Error during Google Sheets synchronization: {str(e)}", 'error')
        return redirect(url_for('view_partners_pledges'))




# Route for 'paystack.html'
@app.route('/paystack')
def paystack():
    return render_template('paystack.html')


# Route for thank you page
@app.route('/thank-you')
def thank_you():
    return render_template('thank_you.html')


# Define a custom filter
@app.template_filter('commas')
def format_commas(value):
    """Format number with commas."""
    return "{:,}".format(value)



@app.route('/success')
def success():
    return "Pledge added successfully!", 200



@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required  # Ensure the user is logged in before accessing the profile edit page
def edit_profile():
    user_id = session.get('user_id')  # Get the user ID from session
    user = User.query.get(user_id)  # Query the user using SQLAlchemy

    if not user:  # Handle the case where the user is not found
        flash('User not found!', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get form data
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        address = request.form.get('address')
        country = request.form.get('country')
        state = request.form.get('state')
        church_branch = request.form.get('church_branch')
        partner_since = request.form.get('partner_since')

        # Update the user profile
        user.name = name
        user.email = email
        user.phone = phone
        user.address = address
        user.country = country
        user.state = state
        user.church_branch = church_branch
        user.partner_since = partner_since

        # Commit the changes to the database
        db.session.commit()

        # Check the admin status of the logged-in user and redirect accordingly
        logged_in_user = User.query.get(session.get('user_id'))  # Assuming user_id is stored in the session
        if logged_in_user and (logged_in_user.is_admin or logged_in_user.is_super_admin):
            flash('Profile updated successfully! You will be redirected to the admin dashboard.', 'success')
            return render_template('profile_edit_success.html', next_url=url_for('admin_dashboard'))
        else:
            flash('Profile updated successfully! You will be redirected to the home page.', 'success')
            return render_template('profile_edit_success.html', next_url=url_for('home2'))

    # Render the edit profile page for GET requests
    return render_template('edit_profile.html', user=user)  # Pass user data to the template



@app.route('/edit-profile-success')
@login_required  # Ensure the user is logged in
def edit_profile_success():
    # Determine the user's role to redirect appropriately
    logged_in_user = User.query.get(session.get('user_id'))  # Assuming user_id is stored in the session
    if logged_in_user and (logged_in_user.is_admin or logged_in_user.is_super_admin):
        next_url = url_for('admin_dashboard')  # Redirect admins to the admin dashboard
    else:
        next_url = url_for('home2')  # Redirect regular users to the home page
    
    return render_template('profile_edit_success.html', next_url=next_url)




API_KEY = os.getenv("EXCHANGE_RATE_API_KEY")
API_URL = f"https://v6.exchangerate-api.com/v6/{API_KEY}/latest/USD"

@app.route('/api/rates', methods=['GET'])
def get_exchange_rates():
    try:
        response = requests.get(API_URL)
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500




# Logout route
@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    session.pop('is_super_admin', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


 
"""
application = app

if __name__ == "__main__":
    application.run(debug=True)


"""

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
