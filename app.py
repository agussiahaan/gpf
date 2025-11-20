
from flask_wtf.csrf import generate_csrf
import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SelectField, TextAreaField, PasswordField, DateField, SelectMultipleField, widgets, FileField
from wtforms.validators import DataRequired, Optional, Length, Email
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from io import BytesIO
import pandas as pd
import re
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.exc import IntegrityError

# Config database via DATABASE_URL (Railway Postgres) or fallback to sqlite
DATABASE_URL = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'gpf.db')

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith('sqlite') else {})
SessionLocal = scoped_session(sessionmaker(bind=engine))
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(150), unique=True, nullable=False)
    password = Column(String(300), nullable=False)
    role = Column(String(50), default='user')
    created_at = Column(String(50))

class Member(Base):
    __tablename__ = 'members'
    id = Column(Integer, primary_key=True)
    name = Column(String(200))
    phone = Column(String(80))
    email = Column(String(200))
    birthdate = Column(String(50))
    gender = Column(String(50))
    commission = Column(String(100))
    status = Column(String(80))
    address = Column(Text)
    services = Column(Text)
    notes = Column(Text)
    created_at = Column(String(50))

# create tables
os.makedirs(os.path.join(os.path.dirname(__file__), 'instance'), exist_ok=True)
Base.metadata.create_all(bind=engine)

# --- Auto-create default admin if no users exist (safe: only creates if table empty) ---
from werkzeug.security import generate_password_hash as _generate_password_hash
from flask_wtf.csrf import CSRFProtect
def create_default_admin():
    db = SessionLocal()
    try:
        try:
            count = db.query(User).count()
        except Exception:
            # if table doesn't exist or other issue, skip
            return
        if count == 0:
            admin = User(username='admin', password=_generate_password_hash('admin123'), role='admin', created_at=datetime.utcnow().isoformat())
            db.add(admin)
            db.commit()
            print('Default admin created: admin / admin123')
    finally:
        db.close()

# run auto-create on startup
create_default_admin()
# --- end auto-create ---


# Flask app
app = Flask(__name__)
from datetime import timedelta
app.permanent_session_lifetime = timedelta(minutes=10)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY','dev_secret_change_me')
csrf = CSRFProtect(app)

@app.context_processor
def inject_csrf():
    return dict(csrf_token=lambda: generate_csrf())

class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()

class MemberForm(FlaskForm):
    name = StringField('Nama', validators=[DataRequired(), Length(max=200)])
    phone = StringField('Telepon', validators=[Optional(), Length(max=80)])
    email = StringField('Email', validators=[Optional(), Email(), Length(max=200)])
    birthdate = DateField('Tanggal Lahir', validators=[Optional()], format='%Y-%m-%d')
    gender = SelectField('Jenis Kelamin', choices=[('','Pilih Jenis Kelamin'),('Laki-laki','Laki-laki'),('Perempuan','Perempuan')], validators=[Optional()])
    commission = SelectField('Komisi', choices=[('', 'Pilih Komisi'),('Umum','Umum'),('Youth','Youth'),('Kids','Kids')], validators=[Optional()])
    status = SelectField('Status', choices=[('','Pilih Status'),('Aktif','Aktif'),('Tidak Aktif','Tidak Aktif')], validators=[Optional()])
    address = TextAreaField('Alamat', validators=[Optional(), Length(max=1000)])
    services = MultiCheckboxField('Jenis Pelayanan', choices=[('Worship Leader','Worship Leader'),('Singer','Singer'),('Usher / Penatalayan','Usher / Penatalayan'),('Keyboard','Keyboard'),('Gitar','Gitar'),('Bass','Bass'),('Drum','Drum'),('Multimedia','Multimedia'),('Soundsystem','Soundsystem'),('Live Streaming','Live Streaming'),('Lainnya','Lainnya')], validators=[Optional()])
    notes = TextAreaField('Catatan', validators=[Optional(), Length(max=2000)])

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=4)])
    role = SelectField('Role', choices=[('user','User'),('admin','Admin')], validators=[DataRequired()])

class ImportForm(FlaskForm):
    file = FileField('File', validators=[DataRequired()])

# helpers


def normalize_phone(phone):
    if not phone:
        return ''
    return re.sub(r'\D', '', str(phone))

def phone_exists(phone):
    phone_n = normalize_phone(phone)
    db = get_db()
    return db.query(Member).filter(Member.phone == phone_n).first() is not None


def get_db():
    return SessionLocal()

def get_user_by_credentials(username, password):
    db = get_db()
    u = db.query(User).filter(User.username==username).first()
    if not u:
        return None
    # try hashed password check, fallback to plain-text comparison if hashing was not used
    try:
        if check_password_hash(u.password, password):
            return u
    except Exception:
        # fallback for non-hashed legacy passwords
        if u.password == password:
            return u
    return None


# auth
from functools import wraps
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        db = get_db()
        u = db.query(User).get(session['user_id'])
        if not u or u.role != 'admin':
            flash('Akses ditolak. Admin saja.','danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return wrapper

# routes
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        username = request.form['username']
        password = request.form['password']
        u = get_user_by_credentials(username, password)
        if u:
            session['user_id'] = u.id
            session['username'] = u.username
            session['role'] = u.role
            flash('Berhasil login','success')
            return redirect(url_for('dashboard'))
        flash('Username atau password salah','danger')
    return render_template('login_page.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    q = request.args.get('q','').strip()
    service = request.args.getlist('service')
    order = request.args.get('order','name')
    gender = request.args.get('gender','')
    db = get_db()
    query = db.query(Member)
    if q:
        like = f"%{q}%"
        query = query.filter((Member.name.ilike(like)) | (Member.phone.ilike(like)) | (Member.email.ilike(like)))
    if service:
        pass
    # Gender filter
    if gender:
        query = query.filter(Member.gender == gender)
        # filter any service occurrence
        conds = []
        for s in service:
            query = query.filter(Member.services.ilike(f"%{s}%"))
    order_map = {'name': Member.name, 'commission': Member.commission, 'status': Member.status}
    order_col = order_map.get(order, Member.name)
    members = query.order_by(order_col).all()
    total_members = len(members)
    return render_template('dashboard.html', members=members, total_members=total_members, q=q, selected_services=service, order=order, gender=gender)

@app.route('/add', methods=['GET','POST'])
@login_required
def add_member():
    services_list = ['Worship Leader','Singer','Usher / Penatalayan','Keyboard','Gitar','Bass','Drum','Multimedia','Soundsystem','Live Streaming','Lainnya']
    if request.method == 'POST':
        name = request.form.get('name')
        phone = request.form.get('phone')
        phone = normalize_phone(phone)
        email = request.form.get('email')
        birthdate = request.form.get('birthdate') or None
        gender = request.form.get('gender')
        commission = request.form.get('commission')
        status = request.form.get('status')
        address = request.form.get('address')
        services = request.form.getlist('services') or []
        notes = request.form.get('notes')
        db = get_db()
        m = Member(name=name, phone=phone, email=email, birthdate=birthdate, gender=gender,
                   commission=commission, status=status, address=address, services=','.join(services),
                   notes=notes, created_at=datetime.utcnow().isoformat())
        db.add(m); db.commit()
        flash('Anggota berhasil ditambahkan','success')
        return redirect(url_for('dashboard'))
    # GET
    selected_services = []
    # render page with empty form
    return render_template('add_member.html', services_list=services_list, selected_services=selected_services)
@app.route('/member/<int:id>/edit', methods=['GET','POST'])

def edit_member(id):
    services_list = ['Worship Leader','Singer','Usher / Penatalayan','Keyboard','Gitar','Bass','Drum','Multimedia','Soundsystem','Live Streaming','Lainnya']
    db = get_db()
    m = db.query(Member).get(id)
    if not m:
        flash('Anggota tidak ditemukan','danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # collect form data first (do not assign directly to model until validated)
        name = request.form.get('name')
        phone_raw = request.form.get('phone')
        phone = normalize_phone(phone_raw)
        email = request.form.get('email')
        birthdate = request.form.get('birthdate') or None
        gender = request.form.get('gender')
        commission = request.form.get('commission')
        status = request.form.get('status')
        address = request.form.get('address')
        services = request.form.getlist('services') or []
        notes = request.form.get('notes')

        # validate phone uniqueness (avoid assigning duplicate to another member)
        if phone:
            existing = db.query(Member).filter(Member.phone == phone, Member.id != m.id).first()
            if existing:
                flash('Nomor telepon sudah digunakan oleh anggota lain. Perubahan dibatalkan.','warning')
                return redirect(url_for('edit_member', id=id))

        # apply updates
        m.name = name
        m.phone = phone
        m.email = email
        m.birthdate = birthdate
        m.gender = gender
        m.commission = commission
        m.status = status
        m.address = address
        m.services = ','.join(services)
        m.notes = notes

        try:
            db.add(m)
            db.commit()
            flash('Anggota diperbarui','success')
        except Exception as e:
            db.rollback()
            flash('Gagal memperbarui anggota: ' + str(e), 'danger')
        return redirect(url_for('dashboard'))

    # GET: prepopulate values
    selected_services = m.services.split(',') if m.services else []
    return render_template('edit_member.html', member=m, services_list=services_list, selected_services=selected_services)
@app.route('/users', methods=['GET','POST'])
@admin_required
def users():
    db = get_db()
    if request.method=='POST':
        form = UserForm()
        if form.validate_on_submit():
            try:
                u = User(username=form.username.data, password=generate_password_hash(form.password.data), role=form.role.data, created_at=datetime.utcnow().isoformat())
                db.add(u); db.commit()
                flash('User ditambah','success')
            except IntegrityError:
                db.rollback()
                flash('Username sudah ada','danger')
        else:
            flash('Data user tidak valid','danger')
    users = db.query(User).order_by(User.id).all()
    return render_template('manage_users.html', users=users)

@app.route('/member/<int:id>/delete', methods=['POST'])
@admin_required
def delete_member(id):
    db = get_db()
    m = db.query(Member).get(id)
    if m:
        db.delete(m); db.commit()
        flash('Anggota dihapus','success')
    return redirect(url_for('dashboard'))

# Import/Export
ALLOWED_EXT = {'csv','xlsx'}
@app.route('/export/<filetype>')
@login_required
def export_data(filetype):
    db = get_db()
    members = db.query(Member).all()
    rows = []
    for m in members:
        rows.append({
            'id': m.id,
            'name': m.name,
            'phone': m.phone,
            'email': m.email,
            'birthdate': m.birthdate,
            'gender': m.gender,
            'commission': m.commission,
            'status': m.status,
            'address': m.address,
            'services': m.services,
            'notes': m.notes,
            'created_at': m.created_at
        })
    df = pd.DataFrame(rows)
    buf = BytesIO()
    if filetype=='csv':
        df.to_csv(buf, index=False)
        buf.seek(0)
        return send_file(buf, mimetype='text/csv', download_name='gpf_members.csv', as_attachment=True)
    else:
        df.to_excel(buf, index=False)
        buf.seek(0)
        return send_file(buf, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', download_name='gpf_members.xlsx', as_attachment=True)




if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT',5000)))

@app.before_request
def session_timeout_check():
    session.modified = True


@csrf.exempt
@app.route('/import', methods=['GET','POST'])
@login_required
def import_data():
    if request.method == 'POST':
        f = request.files.get('file')
        if not f:
            flash('File tidak ditemukan', 'danger')
            return redirect(url_for('import_data'))

        filename = secure_filename(f.filename)
        ext = filename.rsplit('.', 1)[-1].lower()

        if ext not in ['csv', 'xlsx', 'xls']:
            flash('Format file tidak didukung', 'danger')
            return redirect(url_for('import_data'))

        try:
            # baca file
            if ext == 'csv':
                df = pd.read_csv(f, dtype={'phone': str})
            else:
                df = pd.read_excel(f, dtype={'phone': str})

            db = get_db()
            added = 0
            skipped = 0

            for _, row in df.iterrows():
                phone = str(row.get('phone'))
                phone = normalize_phone(phone)

                # skip jika nomor telepon duplikat
                if phone_exists(phone):
                    skipped += 1
                    continue

                m = Member(
                    name=row.get('name'),
                    phone=phone,
                    email=row.get('email'),
                    birthdate=str(row.get('birthdate')),
                    gender=row.get('gender'),
                    commission=row.get('commission'),
                    status=row.get('status'),
                    address=row.get('address'),
                    services=row.get('services'),
                    notes=row.get('notes'),
                    created_at=datetime.utcnow().isoformat()
                )
                db.add(m)
                added += 1

            db.commit()

            flash(f"Import selesai. {added} data ditambahkan, {skipped} duplikat dilewati.", "success")

        except Exception as e:
            flash("Gagal import: " + str(e), "danger")

        return redirect(url_for('dashboard'))

    return render_template('import.html')
