from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message as MailMessage # Renamed to avoid conflict with our Message model
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from werkzeug.utils import secure_filename
from functools import wraps
from sqlalchemy import or_
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key' # Change this for production
app.config['ADMIN_REGISTRATION_KEY'] = 'POLICEKEY123' # Change this in a real app

# --- Database Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Email Configuration (using Gmail as an example) ---
# IMPORTANT: For production, use environment variables to store sensitive data.
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER', 'your-email@gmail.com') # Replace or set environment variable
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS', 'your-app-password')   # Replace or set environment variable
mail = Mail(app)

s = URLSafeTimedSerializer(app.secret_key)
migrate = Migrate(app, db, directory='migrations')

# --- File Upload Configuration ---
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --------- Database Models ---------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_police = db.Column(db.Boolean, default=False)   # <- make sure this exists
  # This MUST exist

class Police(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    phone_number = db.Column(db.String(20))
    station_name = db.Column(db.String(100))
    station_address = db.Column(db.String(200))

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(150))
    status = db.Column(db.String(10), nullable=False)  # 'lost' or 'found'
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    image_filename = db.Column(db.String(100))
    owner = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)
    complaint_type = db.Column(db.String(100), nullable=False)
    user_name = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    image_filename = db.Column(db.String(100))
    is_resolved = db.Column(db.Boolean, default=False, nullable=False, server_default='0')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender_username = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False) # This is our model
    reply = db.Column(db.Text)
    date_sent = db.Column(db.DateTime, default=datetime.utcnow)
    date_replied = db.Column(db.DateTime)
    is_read = db.Column(db.Boolean, default=False)

class Claim(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    claimer_username = db.Column(db.String(100), nullable=False)
    claim_message = db.Column(db.Text, nullable=False)
    date_claimed = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending', nullable=False) # pending, approved, rejected

    # Relationships
    item = db.relationship('Item', backref=db.backref('claims', lazy=True, cascade="all, delete-orphan"))
    user = db.relationship('User', backref=db.backref('claims', lazy=True, cascade="all, delete-orphan"))

# --------- Decorators ---------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def police_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'police_id' not in session:
            flash('You must be logged in as an admin to view this page.')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# --------- Helper Functions ---------
def send_email(recipient, subject, template):
    """Helper function to send an email."""
    msg = MailMessage(
        subject,
        recipients=[recipient],
        html=template,
        sender=app.config.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])
    )
    mail.send(msg)

# --------- Main Routes ---------
@app.route('/')
def index():
    # If user is already logged in, redirect to dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    # Otherwise, show the main landing page
    return render_template('home.html')

@app.route('/dashboard')
@login_required
def dashboard():
    username = session.get('username')
    return render_template('dashboard.html', username=username)

# --------- User Authentication Routes ---------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_police'] = user.is_police
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email address already registered.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password, is_police=False)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate a time-sensitive token
            token = s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)

            # Send the email
            subject = "Password Reset Request"
            email_html = render_template(
                'email/reset_password_email.html',
                username=user.username,
                reset_url=reset_url
            )
            send_email(user.email, subject, email_html)

        # Flash a generic message for security reasons
        flash('If an account with that email exists, a password reset link has been sent.')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # The token is valid for 1 hour (3600 seconds)
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        user.password = generate_password_hash(password)
        db.session.commit()
        flash('Your password has been successfully updated! You can now log in.')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# --------- Admin/Police Authentication Routes ---------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        police_user = Police.query.filter_by(username=username).first()

        if police_user and check_password_hash(police_user.password, password):
            session['police_id'] = police_user.id
            session['police_username'] = police_user.username
            flash('Police login successful!')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin username or password.')
            return redirect(url_for('admin_login'))
    return render_template('admin_login.html')

@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        registration_key = request.form.get('registration_key')

        if registration_key != app.config['ADMIN_REGISTRATION_KEY']:
            flash('Invalid registration key. Access denied.')
            return redirect(url_for('admin_login'))

        hashed_password = generate_password_hash(request.form['password'])
        new_police = Police(
            username=request.form['username'],
            email=request.form['email'],
            password=hashed_password,
            phone_number=request.form['phone_number'],
            station_name=request.form['station_name'],
            station_address=request.form['station_address']
        )
        db.session.add(new_police)
        db.session.commit()
        flash('Admin account created successfully! Please login.')
        return redirect(url_for('admin_login'))
    return render_template('admin_register.html')

@app.route('/admin/dashboard', methods=['GET'])
@police_login_required
def admin_dashboard():
    # Pagination for multiple tables. We'll use different query params for each.
    page_items = request.args.get('page_items', 1, type=int)
    page_users = request.args.get('page_users', 1, type=int)
    page_claims = request.args.get('page_claims', 1, type=int)
    page_complaints = request.args.get('page_complaints', 1, type=int)
    
    items_pagination = Item.query.order_by(Item.date_posted.desc()).paginate(page=page_items, per_page=5)
    users_pagination = User.query.order_by(User.id.asc()).paginate(page=page_users, per_page=5)
    claims_pagination = Claim.query.filter_by(status='pending').order_by(Claim.date_claimed.desc()).paginate(page=page_claims, per_page=5)
    complaints_pagination = Complaint.query.order_by(Complaint.date_posted.desc()).paginate(page=page_complaints, per_page=5)

    # Messages are not paginated for now to keep them simple
    all_messages = Message.query.order_by(Message.date_sent.desc()).all()

    return render_template('admin_dashboard.html',
                           items_pagination=items_pagination,
                           users_pagination=users_pagination,
                           claims_pagination=claims_pagination,
                           complaints_pagination=complaints_pagination,
                           messages=all_messages,
                           username=session.get('police_username'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('police_id', None)
    session.pop('police_username', None)
    flash('You have been logged out from the admin panel.')
    return redirect(url_for('admin_login'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@police_login_required
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)

    # Prevent deleting the 'system' user to protect sample data
    if user_to_delete.username == 'system':
        flash('The default "system" user cannot be deleted.')
        return redirect(url_for('admin_dashboard'))

    # Delete associated data first to avoid integrity errors
    Item.query.filter_by(user_id=user_id).delete()
    Message.query.filter_by(user_id=user_id).delete()
    Claim.query.filter_by(user_id=user_id).delete()

    db.session.delete(user_to_delete)
    db.session.commit()

    flash(f'User "{user_to_delete.username}" and all their associated data have been deleted.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_item/<int:item_id>', methods=['POST'])
@police_login_required
def admin_delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    
    # Also delete the image file if it exists to keep the server clean
    if item.image_filename:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], item.image_filename))
        except OSError:
            pass # Fail silently if file not found, as DB entry is the priority
    
    # Deleting an item should also delete associated claims
    Claim.query.filter_by(item_id=item_id).delete()
    db.session.delete(item)
    db.session.commit()
    flash(f'Item "{item.name}" has been successfully deleted.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/report_item', methods=['POST'])
@police_login_required
def admin_report_item():
    # Find the 'system' user to assign ownership of admin-reported items
    system_user = User.query.filter_by(username='system').first()
    if not system_user:
        # This is a fallback, but the system user should always exist
        flash('Critical error: "system" user not found. Cannot report item.', 'error')
        return redirect(url_for('admin_dashboard'))

    filename = None
    image = request.files.get('image')
    if image and allowed_file(image.filename):
        filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    new_item = Item(
        name=request.form['item_name'],
        description=request.form['description'],
        location=request.form['location'],
        status='found',  # Admin can only report found items
        image_filename=filename,
        owner=system_user.username, # Assign to 'system'
        user_id=system_user.id
    )
    db.session.add(new_item)
    db.session.commit()
    flash('New found item has been successfully reported and is now visible to users.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/update_claim/<int:claim_id>/<action>', methods=['POST'])
@police_login_required
def update_claim(claim_id, action):
    claim = Claim.query.get_or_404(claim_id)
    if action not in ['approved', 'rejected']:
        flash('Invalid action.', 'error')
        return redirect(url_for('admin_dashboard'))

    claim.status = action
    db.session.commit()

    # --- Send Email Notification to User ---
    try:
        claimant = claim.user
        subject = f"Update on your claim for '{claim.item.name}'"
        email_html = render_template(
            'email/claim_status.html',
            username=claimant.username,
            item_name=claim.item.name,
            status=action,
            item_id=claim.item.id
        )
        send_email(claimant.email, subject, email_html)
    except Exception as e:
        flash(f'Claim status updated, but failed to send notification email. Error: {e}', 'warning')

    flash(f'Claim for item "{claim.item.name}" has been {action}.')
    return redirect(url_for('admin_dashboard'))

# --------- Item Management Routes ---------
@app.route('/items')
@login_required
def view_items():
    search_query = request.args.get('q', '')
    query = Item.query

    if search_query:
        search_term = f"%{search_query}%"
        query = query.filter(
            or_(
                Item.name.ilike(search_term),
                Item.description.ilike(search_term),
                Item.location.ilike(search_term)
            )
        )

    all_items = query.order_by(Item.date_posted.desc()).all()
    return render_template('items.html', items=all_items, username=session.get('username'), search_query=search_query)

@app.route('/my_items')
@login_required
def my_items():
    user_id = session.get('user_id')
    items = Item.query.filter_by(user_id=user_id).order_by(Item.date_posted.desc()).all()
    return render_template('my_items.html', items=items, username=session.get('username'))

@app.route('/item/<int:item_id>')
@login_required
def item_details(item_id):
    item = Item.query.get_or_404(item_id)
    return render_template('item_details.html', item=item, username=session.get('username'))

@app.route('/add_item', methods=['GET', 'POST'])
@login_required
def add_item():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        location = request.form['location']
        status = request.form['status']
        image = request.files.get('image')
        filename = None

        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        new_item = Item(
            name=name,
            description=description,
            location=location,
            status=status,
            image_filename=filename,
            owner=session['username'],
            user_id=session['user_id']
        )
        db.session.add(new_item)
        db.session.commit()
        flash('Item added successfully!')
        return redirect(url_for('view_items'))
    return render_template('add_item.html', username=session.get('username'))

@app.route('/edit_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    item = Item.query.get_or_404(item_id)
    if item.user_id != session['user_id']:
        flash('You are not authorized to edit this item.')
        return redirect(url_for('view_items'))

    if request.method == 'POST':
        item.name = request.form['name']
        item.description = request.form['description']
        item.location = request.form['location']
        item.status = request.form['status']
        
        image = request.files.get('image')
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            item.image_filename = filename

        db.session.commit()
        flash('Item updated successfully!')
        return redirect(url_for('item_details', item_id=item.id))
    return render_template('edit_item.html', item=item, username=session.get('username'))

@app.route('/delete_item/<int:item_id>', methods=['POST'])
@login_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    if item.user_id != session['user_id']:
        flash('You are not authorized to delete this item.')
        return redirect(url_for('view_items'))

    db.session.delete(item)
    db.session.commit()
    flash('Item deleted successfully.')
    return redirect(url_for('my_items'))

@app.route('/report_item/<status>', methods=['GET', 'POST'])
@login_required
def report_item(status):
    if status not in ['lost', 'found']:
        flash('Invalid item status specified.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        filename = None
        image = request.files.get('image')
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        new_item = Item(
            name=request.form['item_name'],
            description=request.form['description'],
            location=request.form['location'],
            status=status,  # Use status from URL
            image_filename=filename,
            owner=session['username'],
            user_id=session['user_id']
        )
        db.session.add(new_item)
        db.session.commit()
        flash(f'Successfully reported {status} item!')
        return redirect(url_for('view_items'))

    return render_template('report_item.html', status=status, username=session.get('username'))

# --------- Claim Routes ---------
@app.route('/claim_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def claim_item(item_id):
    item = Item.query.get_or_404(item_id)

    # Prevent users from claiming their own reported items or items that are 'lost'
    if item.status == 'lost' or item.user_id == session['user_id']:
        flash("This item cannot be claimed.", 'error')
        return redirect(url_for('item_details', item_id=item_id))

    # Check if user has already claimed this item
    existing_claim = Claim.query.filter_by(item_id=item_id, user_id=session['user_id']).first()
    if existing_claim:
        flash(f"You have already filed a claim for this item on {existing_claim.date_claimed.strftime('%Y-%m-%d')}. Its status is '{existing_claim.status}'.")
        return redirect(url_for('item_details', item_id=item_id))

    if request.method == 'POST':
        new_claim = Claim(
            item_id=item.id,
            user_id=session['user_id'],
            claimer_username=session['username'],
            claim_message=request.form['claim_message']
        )
        db.session.add(new_claim)
        db.session.commit()
        flash('Your claim has been submitted. An administrator will review it shortly.')
        return redirect(url_for('item_details', item_id=item_id))

    return render_template('claim_item.html', item=item, username=session.get('username'))

@app.route('/my_claims')
@login_required
def my_claims():
    user_id = session['user_id']
    claims = Claim.query.filter_by(user_id=user_id).order_by(Claim.date_claimed.desc()).all()
    return render_template('my_claims.html', claims=claims, username=session.get('username'))

# --------- Complaint Routes ---------
@app.route('/file_complaint', methods=['GET', 'POST'])
@login_required
def file_complaint():
    if request.method == 'POST':
        new_complaint = Complaint(
            item_name=request.form['item_name'],
            complaint_type=request.form['complaint_type'],
            details=request.form['details'],
            user_name=session['username']
        )
        db.session.add(new_complaint)
        db.session.commit()
        flash('Your complaint has been filed successfully.')
        return redirect(url_for('dashboard'))
    return render_template('file_complaint.html', username=session.get('username'))

@app.route('/admin/resolve_complaint/<int:complaint_id>', methods=['POST'])
@police_login_required
def resolve_complaint(complaint_id):
    complaint = Complaint.query.get_or_404(complaint_id)
    complaint.is_resolved = True
    db.session.commit()
    flash(f'Complaint regarding "{complaint.item_name}" has been marked as resolved.')
    return redirect(url_for('admin_dashboard'))

# --------- Messaging Routes ---------
@app.route('/my_messages')
def my_messages():
    # If you later want to display messages from the database, you can query them here.
    return render_template('my_messages.html')

@app.route('/message_admin', methods=['GET', 'POST'])
@login_required
def send_message():
    if request.method == 'POST':
        message_text = request.form.get('message')
        if not message_text:
            flash('Message cannot be empty.')
            return redirect(url_for('send_message'))

        new_message = Message(
            user_id=session['user_id'],
            sender_username=session['username'],
            message=message_text
        )
        db.session.add(new_message)
        db.session.commit()
        flash('Your message has been sent to the administrators.')
        return redirect(url_for('dashboard'))
    return render_template('message_admin.html', username=session.get('username'))

@app.route('/reply_message/<int:message_id>', methods=['POST'])
@police_login_required
def reply_message(message_id):
    message = Message.query.get_or_404(message_id)
    message.reply = request.form.get('reply_text')
    message.date_replied = datetime.utcnow()
    db.session.commit()
    flash('Reply sent successfully.')
    return redirect(url_for('admin_dashboard'))

# --------- Context Processor and Main Execution ---------
@app.context_processor
def inject_user():
    return dict(username=session.get('username'))

def add_sample_data():
    # Check if items exist
    if Item.query.count() == 0:
        # Sample items
        sample_items = [
            Item(name='Laptop Charger', description='A black Dell laptop charger.', location='Library', status='lost', owner='system', user_id=1),
            Item(name='Water Bottle', description='A blue hydroflask with a sticker.', location='Gym', status='found', owner='system', user_id=1),
            Item(name='Keys', description='A set of keys with a red keychain.', location='Cafeteria', status='lost', owner='system', user_id=1)
        ]
        db.session.bulk_save_objects(sample_items)
        db.session.commit()
        print("Added sample items.")

if __name__ == '__main__':
    with app.app_context():
        # The following block is useful for initial setup, but should be used carefully.
        # For schema changes, always use 'flask db migrate' and 'flask db upgrade'.
        # db.create_all() # This is now handled by migrations.
        # if User.query.count() == 0:
        #     default_user = User(username='system', email='system@system.com', password=generate_password_hash('system'))
        #     db.session.add(default_user)
        #     db.session.commit()
        #     print("Created default system user.")
        # add_sample_data()
        pass
    app.run(debug=True)