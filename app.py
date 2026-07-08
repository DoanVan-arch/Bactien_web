import os
import pandas as pd
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import re  # <-- ĐẢM BẢO CÓ DÒNG NÀY Ở NGAY ĐẦU FILE

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024 # Giới hạn 50MB

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- BIẾN CACHE ĐỂ TĂNG TỐC TÌM KIẾM ---
# Lưu trữ dữ liệu dưới dạng: {'ten_file.xlsx': {'Sheet1': DataFrame, 'Sheet2': DataFrame}}
DATA_CACHE = {}

def load_file_to_cache(filename, filepath):
    """Đọc file Excel và lưu vào RAM (DATA_CACHE)"""
    try:
        xls = pd.read_excel(filepath, sheet_name=None, dtype=str)
        for sheet_name in xls:
            xls[sheet_name] = xls[sheet_name].fillna('')
        DATA_CACHE[filename] = xls
        print(f" Đã cache file: {filename}")
    except Exception as e:
        print(f" Lỗi cache file {filename}: {e}")

def init_cache():
    """Chạy khi khởi động server, nạp toàn bộ file vào RAM"""
    print("Đang nạp dữ liệu vào bộ nhớ đệm để tăng tốc...")
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        if filename.endswith(('.xlsx', '.xls')):
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            load_file_to_cache(filename, filepath)
    print("Hoàn tất nạp dữ liệu!")

# --- MODEL CƠ SỞ DỮ LIỆU ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), default='viewer')

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

# --- CÁC ROUTES AUTH & MANAGE USERS GIỮ NGUYÊN (như cũ) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('search'))
        flash('Sai tên đăng nhập hoặc mật khẩu.')
    return render_template('login.html')

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
        if User.query.filter_by(username=username).first():
            flash('Tên đăng nhập đã tồn tại.')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, password=hashed_password, role='viewer')
            db.session.add(new_user)
            db.session.commit()
            flash('Tạo tài khoản người xem thành công!')
            return redirect(url_for('manage_users'))
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/delete_user/<int:user_id>')
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        flash('Không thể xóa tài khoản Admin gốc.')
    else:
        db.session.delete(user)
        db.session.commit()
        flash('Đã xóa tài khoản thành công.')
    return redirect(url_for('manage_users'))

# --- LOGIC UPLOAD MỚI: XỬ LÝ REPLACE VÀ APPEND ---
@app.route('/upload', methods=['GET', 'POST'])
@login_required
@admin_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Không tìm thấy file')
            return redirect(request.url)
            
        file = request.files['file']
        upload_mode = request.form.get('upload_mode', 'replace') # Mặc định là thay thế
        
        if file.filename == '':
            flash('Chưa chọn file nào')
            return redirect(request.url)
            
        if file and file.filename.endswith(('.xlsx', '.xls')):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            try:
                if upload_mode == 'append' and os.path.exists(filepath):
                    # CHẾ ĐỘ THÊM: Đọc cả 2 file và nối lại
                    old_data = pd.read_excel(filepath, sheet_name=None, dtype=str)
                    new_data = pd.read_excel(file, sheet_name=None, dtype=str)
                    
                    with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
                        # Lấy tất cả các sheet từ cả file cũ và mới
                        all_sheets = set(old_data.keys()).union(set(new_data.keys()))
                        for sheet in all_sheets:
                            if sheet in old_data and sheet in new_data:
                                # Nếu sheet có ở cả 2 file, nối dữ liệu vào bên dưới
                                combined = pd.concat([old_data[sheet], new_data[sheet]], ignore_index=True)
                            elif sheet in old_data:
                                combined = old_data[sheet]
                            else:
                                combined = new_data[sheet]
                            # Lưu vào ổ cứng
                            combined.to_excel(writer, sheet_name=sheet, index=False)
                    flash('Đã nối thêm dữ liệu vào file thành công!')
                else:
                    # CHẾ ĐỘ THAY THẾ (hoặc file chưa tồn tại)
                    file.save(filepath)
                    flash('Đã tải và lưu file mới thành công!')
                
                # Cập nhật lại bộ nhớ đệm (Cache) cho file này
                load_file_to_cache(filename, filepath)
                return redirect(url_for('search'))
                
            except Exception as e:
                flash(f'Lỗi khi xử lý file: {str(e)}')
                
        else:
            flash('Chỉ hỗ trợ file Excel (.xlsx, .xls)')
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

    if request.method == 'POST':
        query = request.form.get('query', '').strip()
        
        # NẾU LÀ ADMIN: Cho phép chọn file cụ thể hoặc tìm tất cả. NẾU LÀ USER: Ép buộc tìm tất cả file.
        if current_user.role == 'admin':
            selected_file = request.form.get('file', '')
        else:
            selected_file = '' # Trống nghĩa là tìm trên tất cả các file

        if query:
            # Xác định danh sách các file cần quét dữ liệu
            if selected_file and selected_file in DATA_CACHE:
                files_to_scan = [selected_file]
            else:
                files_to_scan = list(DATA_CACHE.keys())
            
            try:
                for file_name in files_to_scan:
                    xls_data = DATA_CACHE.get(file_name, {})
                    
                    for sheet_name, df in xls_data.items():
                        # Kiểm tra xem sheet có chứa định dạng năm (Ví dụ: 2024-2026) hay không
                        if re.search(r'\d{4}\s*-\s*\d{4}', str(sheet_name)):
                            
                            # --- LOGIC TÌM KIẾM NÂNG CAO (XỬ LÝ * VÀ |) ---
                            # Chuyển toàn bộ dòng thành một chuỗi văn bản viết thường để quét nhanh
                            row_strings = df.astype(str).apply(lambda x: ' '.join(x), axis=1).str.lower()
                            
                            # Tách theo dấu toán tử OR (|) trước
                            or_groups = query.lower().split('|')
                            final_mask = pd.Series(False, index=df.index)
                            
                            for group in or_groups:
                                if not group.strip():
                                    continue
                                # Tách theo dấu toán tử AND (*) bên trong nhóm OR
                                and_tokens = group.split('*')
                                group_mask = pd.Series(True, index=df.index)
                                
                                for token in and_tokens:
                                    token = token.strip()
                                    if token:
                                        group_mask = group_mask & row_strings.str.contains(token, regex=False)
                                
                                # Gộp kết quả các nhóm bằng toán tử OR
                                final_mask = final_mask | group_mask
                            
                            matches = df[final_mask]
                            if not matches.empty:
                                # Gộp kết quả theo Tên Sheet (Ẩn hoàn toàn tên file đối với người dùng)
                                if sheet_name in results:
                                    results[sheet_name].extend(matches.to_dict('records'))
                                else:
                                    results[sheet_name] = matches.to_dict('records')
                        else:
                            # ĐỐI VỚI CÁC SHEET CHỈ HIỂN THỊ: Gộp toàn bộ dữ liệu gốc ra ngoài
                            if not df.empty:
                                if sheet_name in display_only_data:
                                    display_only_data[sheet_name].extend(df.to_dict('records'))
                                else:
                                    display_only_data[sheet_name] = df.to_dict('records')
                                    
            except Exception as e:
                flash(f'Lỗi khi xử lý dữ liệu tìm kiếm: {str(e)}')

    return render_template('search.html', 
                           files=files, 
                           results=results, 
                           query=query, 
                           selected_file=selected_file,
                           display_only_data=display_only_data)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin()
    init_cache()
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)  # Enable threaded mode for handling multiple requests
