import os
import re
import json
import pandas as pd
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

DATA_CACHE = {}

def load_file_to_cache(filename, filepath):
    try:
        xls = pd.read_excel(filepath, sheet_name=None, dtype=str)
        for sheet_name in xls:
            xls[sheet_name] = xls[sheet_name].fillna('')
        DATA_CACHE[filename] = xls
        print(f"Đã nạp bộ đệm file: {filename}")
    except Exception as e:
        print(f"Lỗi nạp bộ đệm file {filename}: {e}")

def init_cache():
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        if filename.endswith(('.xlsx', '.xls')):
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            load_file_to_cache(filename, filepath)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), default='viewer')
    is_active = db.Column(db.Boolean, default=True)
    allowed_ips = db.Column(db.String(255), nullable=True) 
    column_permissions = db.Column(db.Text, nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            flash('Bạn không có quyền thực hiện chức năng này.')
            return redirect(url_for('search'))
        return f(*args, **kwargs)
    return decorated_function

def create_admin():
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        hashed_password = generate_password_hash('123456', method='pbkdf2:sha256')
        new_admin = User(username='admin', password=hashed_password, role='admin')
        db.session.add(new_admin)
        db.session.commit()

def get_client_ip():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip:
        client_ip = client_ip.split(',')[0].strip()
    return client_ip

@app.route('/login', methods=['GET', 'POST'])
def login():
    client_ip = get_client_ip()
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            if not user.is_active:
                flash('Tài khoản của bạn hiện đang bị khóa.')
                return render_template('login.html', client_ip=client_ip)
            
            if user.allowed_ips and user.role != 'admin':
                allowed_ranges = [ip.strip() for ip in user.allowed_ips.split(',') if ip.strip()]
                if allowed_ranges and not any(client_ip.startswith(r) for r in allowed_ranges):
                    flash(f'⚠️ TRUY CẬP BỊ TỪ CHỐI: IP máy trạm ({client_ip}) chưa được cấp phép. Vui lòng liên hệ Admin.')
                    return render_template('login.html', client_ip=client_ip)

            login_user(user)
            return redirect(url_for('search'))
            
        flash('Sai tên đăng nhập hoặc mật khẩu.')
    return render_template('login.html', client_ip=client_ip)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_users():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'viewer')
        if User.query.filter_by(username=username).first():
            flash('Tên đăng nhập đã tồn tại.')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, password=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash('Tạo tài khoản thành công!')
            return redirect(url_for('manage_users'))
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == 'admin': 
        flash('Không thể thay đổi cấu hình của tài khoản Admin gốc.')
        return redirect(url_for('manage_users'))
    if request.method == 'POST':
        user.is_active = 'is_active' in request.form
        user.allowed_ips = request.form.get('allowed_ips')
        enable_perms = request.form.get('enable_permissions')
        if enable_perms == 'yes':
            perms = request.form.get('column_permissions')
            if perms: user.column_permissions = perms
        else:
            user.column_permissions = None
        new_password = request.form.get('password')
        if new_password: user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.session.commit()
        flash('Cập nhật cấu hình thành công!')
        return redirect(url_for('manage_users'))
    file_metadata = {}
    for fname, f_data in DATA_CACHE.items():
        file_metadata[fname] = {}
        for sname, df in f_data.items(): file_metadata[fname][sname] = df.columns.tolist()
    current_perms = json.loads(user.column_permissions) if user.column_permissions else {}
    return render_template('edit_user.html', user=user, file_metadata=file_metadata, current_perms=current_perms)

@app.route('/delete_user/<int:user_id>')
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == 'admin':
        flash('Không thể xóa tài khoản Admin gốc (root).')
    elif user.id == current_user.id:
        flash('Bạn không thể tự xóa chính tài khoản của mình.')
    else:
        db.session.delete(user)
        db.session.commit()
        flash('Đã xóa tài khoản thành công.')
    return redirect(url_for('manage_users'))

# =========================================================
# ROUTE MỚI: XỬ LÝ THAO TÁC HÀNG LOẠT (BULK ACTIONS)
# =========================================================
@app.route('/bulk_action', methods=['POST'])
@login_required
@admin_required
def bulk_action():
    user_ids = request.form.getlist('user_ids')
    action = request.form.get('action')
    
    if not user_ids:
        flash('Vui lòng chọn ít nhất một tài khoản để thao tác.')
        return redirect(url_for('manage_users'))
        
    users_to_process = User.query.filter(User.id.in_(user_ids)).all()
    
    # THAO TÁC 1: XÓA HÀNG LOẠT
    if action == 'delete':
        deleted_count = 0
        for u in users_to_process:
            if u.username == 'admin' or u.id == current_user.id:
                continue # Bỏ qua Admin gốc và bản thân
            db.session.delete(u)
            deleted_count += 1
        db.session.commit()
        flash(f'Đã xóa {deleted_count} tài khoản thành công.')
        return redirect(url_for('manage_users'))
        
    # THAO TÁC 2: CHUYỂN HƯỚNG SANG TRANG CẤU HÌNH HÀNG LOẠT
    elif action == 'edit':
        # Loại bỏ admin gốc khỏi danh sách cấu hình hàng loạt
        users_to_edit = [u for u in users_to_process if u.username != 'admin']
        if not users_to_edit:
            flash('Các tài khoản được chọn không hợp lệ để cấu hình.')
            return redirect(url_for('manage_users'))
            
        file_metadata = {}
        for fname, f_data in DATA_CACHE.items():
            file_metadata[fname] = {}
            for sname, df in f_data.items(): file_metadata[fname][sname] = df.columns.tolist()
            
        return render_template('bulk_edit.html', users=users_to_edit, file_metadata=file_metadata)
    
    return redirect(url_for('manage_users'))

@app.route('/save_bulk_edit', methods=['POST'])
@login_required
@admin_required
def save_bulk_edit():
    user_ids = request.form.getlist('user_ids')
    if not user_ids:
        return redirect(url_for('manage_users'))
        
    users = User.query.filter(User.id.in_(user_ids)).all()
    
    is_active = 'is_active' in request.form
    allowed_ips = request.form.get('allowed_ips')
    enable_perms = request.form.get('enable_permissions')
    
    perms = request.form.get('column_permissions') if enable_perms == 'yes' else None
    new_password = request.form.get('password')
    
    for u in users:
        if u.username == 'admin':
            continue # Bảo vệ an toàn tuyệt đối
            
        u.is_active = is_active
        u.allowed_ips = allowed_ips
        u.column_permissions = perms
        if new_password:
            u.password = generate_password_hash(new_password, method='pbkdf2:sha256')
            
    db.session.commit()
    flash(f'Cập nhật cấu hình hàng loạt cho {len(users)} tài khoản thành công!')
    return redirect(url_for('manage_users'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
@admin_required
def upload_file():
    if request.method == 'POST':
        file = request.files.get('file')
        upload_mode = request.form.get('upload_mode', 'replace')
        if file and file.filename.endswith(('.xlsx', '.xls')):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            try:
                if upload_mode == 'append' and os.path.exists(filepath):
                    old_data = pd.read_excel(filepath, sheet_name=None, dtype=str)
                    new_data = pd.read_excel(file, sheet_name=None, dtype=str)
                    with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
                        all_sheets = set(old_data.keys()).union(set(new_data.keys()))
                        for sheet in all_sheets:
                            if sheet in old_data and sheet in new_data: combined = pd.concat([old_data[sheet], new_data[sheet]], ignore_index=True)
                            elif sheet in old_data: combined = old_data[sheet]
                            else: combined = new_data[sheet]
                            combined.to_excel(writer, sheet_name=sheet, index=False)
                else: file.save(filepath)
                load_file_to_cache(filename, filepath)
                flash('Xử lý file thành công!')
                return redirect(url_for('search'))
            except Exception as e: flash(f'Lỗi khi xử lý file: {str(e)}')
    return render_template('upload.html')

@app.route('/', methods=['GET', 'POST'])
@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    files = list(DATA_CACHE.keys())
    results = {}
    query = ""
    selected_file = ""
    display_only_data = {}
    user_perms = json.loads(current_user.column_permissions) if current_user.role != 'admin' and current_user.column_permissions else None
    if request.method == 'POST':
        query = request.form.get('query', '').strip()
        selected_file = request.form.get('file', '') if current_user.role == 'admin' else ''
        if query:
            files_to_scan = [selected_file] if selected_file and selected_file in DATA_CACHE else list(DATA_CACHE.keys())
            try:
                for file_name in files_to_scan:
                    xls_data = DATA_CACHE.get(file_name, {})
                    for sheet_name, df in xls_data.items():
                        allowed_cols = df.columns.tolist()
                        if user_perms is not None:
                            if file_name not in user_perms or sheet_name not in user_perms[file_name]: continue
                            allowed_cols = [c for c in user_perms[file_name][sheet_name] if c in df.columns]
                            if not allowed_cols: continue
                        if re.search(r'\d{4}\s*-\s*\d{4}', str(sheet_name)):
                            row_strings = df.astype(str).apply(lambda x: ' '.join(x), axis=1).str.lower()
                            or_groups = query.lower().split('|')
                            final_mask = pd.Series(False, index=df.index)
                            for group in or_groups:
                                if not group.strip(): continue
                                and_tokens = group.split('*')
                                group_mask = pd.Series(True, index=df.index)
                                for token in and_tokens:
                                    token = token.strip()
                                    if token: group_mask = group_mask & row_strings.str.contains(token, regex=False)
                                final_mask = final_mask | group_mask
                            matches = df[final_mask]
                            if not matches.empty:
                                matches = matches[allowed_cols]
                                if sheet_name in results: results[sheet_name].extend(matches.to_dict('records'))
                                else: results[sheet_name] = matches.to_dict('records')
                        else:
                            if not df.empty:
                                df_filtered = df[allowed_cols]
                                if sheet_name in display_only_data: display_only_data[sheet_name].extend(df_filtered.to_dict('records'))
                                else: display_only_data[sheet_name] = df_filtered.to_dict('records')
            except Exception as e: flash(f'Lỗi dữ liệu: {str(e)}')
    return render_template('search.html', files=files, results=results, query=query, selected_file=selected_file, display_only_data=display_only_data)

with app.app_context():
    db.create_all()
    create_admin()
init_cache()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)  # Enable threaded mode for handling multiple requests
