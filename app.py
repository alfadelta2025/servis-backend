import os
import io
import json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from sqlalchemy import create_engine, Column, Integer, String, Float, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt, JWTManager
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import Paragraph
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT

# --- App Configuration ---
app = Flask(__name__)
CORS(app)
app.config['JSON_AS_ASCII'] = False

# --- JWT Configuration ---
app.config["JWT_SECRET_KEY"] = "bu-anahtari-mutlaka-degistirin"  # Değiştirin!
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=30)  # Token süresini 30 güne çıkarır
jwt = JWTManager(app)

# --- File/Config Folders ---
UPLOAD_FOLDER = 'uploads'
CONFIG_FOLDER = 'config'
LOGO_FOLDER = os.path.join(UPLOAD_FOLDER, 'logos')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CONFIG_FOLDER, exist_ok=True)
os.makedirs(LOGO_FOLDER, exist_ok=True)
SETTINGS_FILE = os.path.join(CONFIG_FOLDER, 'settings.json')

# Türkçe karakter desteği için fontları ReportLab'e kaydedin
try:
    pdfmetrics.registerFont(TTFont('DejaVuSans', 'fonts/DejaVuSans.ttf'))
    pdfmetrics.registerFont(TTFont('DejaVuSans-Bold', 'fonts/DejaVuSans-Bold.ttf'))
    print("Fontlar başarıyla kaydedildi.")
except Exception as e:
    print(f"Hata: Font dosyası yüklenemedi. 'fonts/' klasöründeki dosyalardan emin olun. Hata: {e}")

# --- Database Configuration ---
import os

# Render'dan gelen DATABASE_URL ortam değişkenini kullanır
# Eğer bu değişken yoksa (yerel geliştirme için), SQLite kullanır
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///servis.db"

engine = create_engine(DATABASE_URL, echo=False)
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)
session = SessionLocal()

# --- Database Models ---
# ... (Diğer kodunuz aynı kalacak)

# --- Database Models ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default='user')

class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    marka = Column(String)
    model = Column(String)
    seri_no = Column(String)
    kurum = Column(String)
    alinma_tarihi = Column(String)
    aksesuar = Column(String)
    ariza = Column(Text)
    tespit = Column(Text)
    resim1 = Column(String)
    resim2 = Column(String)
    resim3 = Column(String)
    onarim_resim1 = Column(String)
    onarim_resim2 = Column(String)
    onarim_resim3 = Column(String)
    geri_teslim_tarihi = Column(String)
    personel = Column(String)
    maliyet = Column(Float)
    servis_ucreti = Column(Float)
    status = Column(String, default='open')
    completed_by = Column(String)
    teklif_durumu = Column(String, default='Teklif Bekliyor')
    iletisim_kisi = Column(String)
    iletisim_tel = Column(String)
    submitted_by = Column(String, index=True)

Base.metadata.create_all(bind=engine)

# --- Initial Admin User Creation ---
with app.app_context():
    db_session = SessionLocal()
    if not db_session.query(User).filter_by(username="admin").first():
        admin_user = User(
            username="admin",
            password_hash=generate_password_hash("adm123"),
            role="admin"
        )
        db_session.add(admin_user)
        db_session.commit()
    db_session.close()

# --- Helper Functions ---
def device_to_dict(d):
    return {
        "id": d.id, "marka": d.marka, "model": d.model, "seri_no": d.seri_no,
        "kurum": d.kurum, "alinma_tarihi": d.alinma_tarihi, "aksesuar": d.aksesuar,
        "ariza": d.ariza, "tespit": d.tespit, "resim1": d.resim1, "resim2": d.resim2,
        "resim3": d.resim3, "onarim_resim1": d.onarim_resim1, "onarim_resim2": d.onarim_resim2,
        "onarim_resim3": d.onarim_resim3, "geri_teslim_tarihi": d.geri_teslim_tarihi,
        "personel": d.personel, "maliyet": d.maliyet, "servis_ucreti": d.servis_ucreti,
        "status": d.status, "completed_by": d.completed_by,
        "teklif_durumu": d.teklif_durumu,
        "iletisim_kisi": d.iletisim_kisi,
        "iletisim_tel": d.iletisim_tel,
        "submitted_by": d.submitted_by
    }

def get_current_user_role():
    return get_jwt().get("role")

def get_current_user_identity():
    return get_jwt_identity()

def is_admin():
    return get_current_user_role() == "admin"

def get_company_settings():
    """Reads company settings from the JSON file."""
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_company_settings(settings):
    """Saves company settings to the JSON file."""
    with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
        json.dump(settings, f, ensure_ascii=False, indent=4)

def generate_pdf(device, form_type):
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    p.setFont('DejaVuSans', 12)
    
    settings = get_company_settings()
    logo_path = settings.get('logo_path')
    company_name = settings.get('firma_adi', 'Firma Adı')
    company_address = settings.get('adresi', 'Firma Adresi')
    company_tel = settings.get('telefon', 'Telefon')
    company_email = settings.get('email', 'E-posta')
    
    logo_width = 2 * cm
    logo_height = 2 * cm
    logo_x = 2 * cm
    logo_y = A4[1] - 2 * cm - logo_height
    text_x = logo_x + logo_width + 1 * cm
    text_y = A4[1] - 2 * cm
    
    if logo_path and os.path.exists(logo_path):
        p.drawImage(logo_path, logo_x, logo_y, width=logo_width, height=logo_height)
        
    p.setFont('DejaVuSans-Bold', 16)
    title = ""
    if form_type == "teslim_alma":
        title = "Cihaz Teslim Alma Formu"
    elif form_type == "teslim_etme":
        title = "Cihaz Teslim Etme Formu"
    elif form_type == "teklif":
        title = "Teklif Formu"
    p.drawCentredString(A4[0] / 2, A4[1] - 4 * cm, title)

    p.setFont('DejaVuSans', 12)
    current_y = A4[1] - 6 * cm
    p.drawString(2 * cm, current_y, f"Marka: {device.marka}")
    current_y -= 0.5 * cm
    p.drawString(2 * cm, current_y, f"Model: {device.model}")
    current_y -= 0.5 * cm
    p.drawString(2 * cm, current_y, f"Seri No: {device.seri_no}")
    current_y -= 0.5 * cm
    p.drawString(2 * cm, current_y, f"Kurum: {device.kurum}")
    current_y -= 0.5 * cm
    p.drawString(2 * cm, current_y, f"Aksesuar: {device.aksesuar}")
    current_y -= 0.5 * cm
    p.drawString(2 * cm, current_y, f"İletişim Kişisi: {device.iletisim_kisi}")
    current_y -= 0.5 * cm
    p.drawString(2 * cm, current_y, f"İletişim Tel: {device.iletisim_tel}")
    current_y -= 0.5 * cm
    p.drawString(2 * cm, current_y, f"Arıza: {device.ariza}")
    
    # YENİ EKLENEN KISIM: Teslim Alma Formu için alınma tarihini ekle
    if form_type == "teslim_alma":
        current_y -= 0.5 * cm
        p.drawString(2 * cm, current_y, f"Alınma Tarihi: {device.alinma_tarihi}")
        
    if form_type == "teslim_etme" or form_type == "teklif":
        current_y -= 1 * cm
        p.drawString(2 * cm, current_y, f"Tespit Edilenler: {device.tespit}")
        
    if form_type == "teslim_etme":
        current_y -= 0.5 * cm
        p.drawString(2 * cm, current_y, f"Geri Teslim Tarihi: {device.geri_teslim_tarihi}")

    if form_type == "teklif":
        current_y -= 1 * cm
        p.drawString(2 * cm, current_y, f"Maliyet: {device.maliyet} TL")
        current_y -= 0.5 * cm
        p.drawString(2 * cm, current_y, f"Servis Ücreti: {device.servis_ucreti} TL")
        current_y -= 0.5 * cm
        p.drawString(2 * cm, current_y, f"Toplam Teklif: {device.maliyet + device.servis_ucreti} TL")
    
    p.showPage()
    p.save()
    buffer.seek(0)
    return buffer

# --- Auth Routes ---
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Kullanıcı adı ve şifre gereklidir"}), 400
    user = session.query(User).filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        additional_claims = {"role": user.role}
        access_token = create_access_token(identity=username, additional_claims=additional_claims)
        return jsonify(access_token=access_token)
    return jsonify({"error": "Geçersiz kullanıcı adı veya şifre"}), 401

# --- User Management Routes ---
@app.route("/users", methods=["GET"])
@jwt_required()
def get_users():
    if not is_admin():
        return jsonify({"error": "Yetkiniz yok"}), 403
    users = session.query(User).all()
    return jsonify([{"id": u.id, "username": u.username, "role": u.role} for u in users])

@app.route("/users", methods=["POST"])
@jwt_required()
def add_user():
    if not is_admin():
        return jsonify({"error": "Yetkiniz yok"}), 403
    data = request.json
    username, password, role = data.get("username"), data.get("password"), data.get("role", "user")
    if not username or not password:
        return jsonify({"error": "Kullanıcı adı ve şifre gereklidir"}), 400
    if role not in ['admin', 'user', 'customer']:
        return jsonify({"error": "Geçersiz rol"}), 400
    if session.query(User).filter_by(username=username).first():
        return jsonify({"error": "Bu kullanıcı adı zaten mevcut"}), 409
    new_user = User(username=username, password_hash=generate_password_hash(password), role=role)
    session.add(new_user)
    session.commit()
    return jsonify({"message": f"{username} kullanıcısı oluşturuldu"}), 201

@app.route("/users/<int:user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    if not is_admin():
        return jsonify({"error": "Yetkiniz yok"}), 403
    user = session.query(User).get(user_id)
    if not user:
        return jsonify({"error": "Kullanıcı bulunamadı"}), 404
    if user.username == "admin":
        return jsonify({"error": "Admin kullanıcısı silinemez"}), 400
    session.delete(user)
    session.commit()
    return jsonify({"message": "Kullanıcı silindi"})

# --- Company Settings Routes (NEW) ---
@app.route("/settings", methods=["GET"])
@jwt_required()
def get_settings():
    if not is_admin():
        return jsonify({"error": "Yetkiniz yok"}), 403
    settings = get_company_settings()
    return jsonify(settings)

@app.route("/settings", methods=["POST"])
@jwt_required()
def update_settings():
    if not is_admin():
        return jsonify({"error": "Yetkiniz yok"}), 403
    
    settings = get_company_settings()
    
    if request.files:
        if 'logo' in request.files:
            logo_file = request.files['logo']
            if logo_file.filename == '':
                return jsonify({"error": "Logo dosyası seçilmedi"}), 400
            
            if 'logo_path' in settings and os.path.exists(settings['logo_path']):
                os.remove(settings['logo_path'])
            
            filename = logo_file.filename
            file_extension = os.path.splitext(filename)[1].lower()
            if file_extension not in ['.png', '.jpg', '.jpeg']:
                return jsonify({"error": "Desteklenmeyen logo formatı. PNG veya JPG kullanın."}), 400
            
            logo_path = os.path.join(LOGO_FOLDER, f"logo{file_extension}")
            logo_file.save(logo_path)
            settings['logo_path'] = logo_path
    
    if request.form:
        if 'firma_adi' in request.form: settings['firma_adi'] = request.form['firma_adi']
        if 'adresi' in request.form: settings['adresi'] = request.form['adresi']
        if 'telefon' in request.form: settings['telefon'] = request.form['telefon']
        if 'email' in request.form: settings['email'] = request.form['email']

    save_company_settings(settings)
    
    return jsonify({"message": "Ayarlar başarıyla güncellendi", "settings": settings}), 200

# --- Device Routes ---
@app.route("/devices", methods=["GET"])
@jwt_required()
def get_devices():
    query = request.args.get("q", "")
    devices_query = session.query(Device)
    
    if get_current_user_role() == 'customer':
        devices_query = devices_query.filter(Device.submitted_by == get_current_user_identity())
    
    if query and len(query) >= 3 and get_current_user_role() != 'customer':
        search_term = f"%{query}%"
        devices_query = devices_query.filter(
            (Device.marka.ilike(search_term)) | (Device.model.ilike(search_term)) |
            (Device.seri_no.ilike(search_term)) | (Device.kurum.ilike(search_term)) |
            (Device.ariza.ilike(search_term)) | (Device.tespit.ilike(search_term)) |
            (Device.iletisim_kisi.ilike(search_term)) | (Device.iletisim_tel.ilike(search_term))
        )
    
    devices = devices_query.order_by(Device.id.desc()).all()
    return jsonify([device_to_dict(d) for d in devices])

@app.route("/devices", methods=["POST"])
@jwt_required()
def add_device():
    data = request.json
    current_user = get_current_user_identity()
    user_role = get_current_user_role()
    if user_role == 'customer':
        allowed_fields = ['marka', 'model', 'kurum', 'iletisim_kisi', 'ariza']
        filtered_data = {key: data[key] for key in allowed_fields if key in data}
        new_device = Device(**filtered_data)
    else:
        data.pop('id', None)
        data.pop('status', None)
        data.pop('completed_by', None)
        new_device = Device(**data)
    
    new_device.submitted_by = current_user
    if not new_device.alinma_tarihi:
        new_device.alinma_tarihi = datetime.now().strftime('%Y-%m-%d')
    
    session.add(new_device)
    session.commit()
    
    return jsonify({"message": "Cihaz başarıyla eklendi", "id": new_device.id}), 201

@app.route("/devices/<int:device_id>", methods=["GET"])
@jwt_required()
def get_device(device_id):
    device = session.query(Device).get(device_id)
    if not device:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    if get_current_user_role() == 'customer' and device.submitted_by != get_current_user_identity():
        return jsonify({"error": "Yetkiniz yok"}), 403
    return jsonify(device_to_dict(device))

@app.route("/devices/<int:device_id>", methods=["PUT"])
@jwt_required()
def update_device(device_id):
    if get_current_user_role() == 'customer':
        return jsonify({"error": "Güncelleme yetkiniz yok"}), 403
    
    device = session.query(Device).get(device_id)
    if not device:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    
    if device.status == 'completed' and not is_admin():
        return jsonify({"error": "Tamamlanmış bir kayıt kullanıcı tarafından değiştirilemez"}), 403
    
    data = request.json
    data.pop('id', None)
    data.pop('status', None)
    data.pop('completed_by', None)
    
    for key, value in data.items():
        setattr(device, key, value)
    
    session.commit()
    return jsonify({"message": "Cihaz başarıyla güncellendi", "device": device_to_dict(device)})


@app.route("/devices/<int:device_id>", methods=["DELETE"])
@jwt_required()
def delete_device(device_id):
    if not is_admin():
        return jsonify({"error": "Yetkiniz yok"}), 403
    
    device = session.query(Device).get(device_id)
    if not device:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    
    session.delete(device)
    session.commit()
    
    return jsonify({"message": "Cihaz başarıyla silindi"})

@app.route("/devices/<int:device_id>/complete", methods=["POST"])
@jwt_required()
def complete_device(device_id):
    if not is_admin():
        return jsonify({"error": "Yetkiniz yok"}), 403
    
    device = session.query(Device).get(device_id)
    if not device:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    
    device.status = 'completed'
    device.completed_by = get_current_user_identity()
    
    # Geri teslim tarihini otomatik olarak ayarla
    device.geri_teslim_tarihi = datetime.now().strftime('%Y-%m-%d')

    session.commit()
    return jsonify({"message": "Cihaz tamamlandı olarak işaretlendi"})

@app.route('/devices/<int:device_id>/upload', methods=['POST'])
@jwt_required()
def upload_file(device_id):
    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'Dosya bulunamadı'}), 400
    
    index = request.form.get('index')
    if index is None or not index.isdigit():
        return jsonify({'error': 'Geçersiz indeks'}), 400
    
    index = int(index)
    
    file_extension = os.path.splitext(file.filename)[1]
    filename = f"{device_id}_{index}{file_extension}"
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)
    
    device = session.query(Device).get(device_id)
    if device:
        if index == 1:
            device.resim1 = os.path.join(UPLOAD_FOLDER, filename)
        elif index == 2:
            device.resim2 = os.path.join(UPLOAD_FOLDER, filename)
        elif index == 3:
            device.resim3 = os.path.join(UPLOAD_FOLDER, filename)
        elif index == 4:
            device.onarim_resim1 = os.path.join(UPLOAD_FOLDER, filename)
        elif index == 5:
            device.onarim_resim2 = os.path.join(UPLOAD_FOLDER, filename)
        elif index == 6:
            device.onarim_resim3 = os.path.join(UPLOAD_FOLDER, filename)
        session.commit()
    
    return jsonify({'message': 'Dosya başarıyla yüklendi', 'filename': filename}), 200

# Statik dosyaları sunmak için rota
@app.route('/uploads/<path:filename>')
def serve_uploads(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route("/devices/<int:device_id>/generate-teslim-alma-formu", methods=["GET"])
@jwt_required()
def generate_teslim_alma_formu_route(device_id):
    device = session.query(Device).get(device_id)
    if not device:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    pdf_buffer = generate_pdf(device, "teslim_alma")
    return send_file(pdf_buffer, as_attachment=True, download_name=f"teslim_alma_{device_id}.pdf", mimetype='application/pdf')

@app.route("/devices/<int:device_id>/generate-teslim-etme-formu", methods=["GET"])
@jwt_required()
def generate_teslim_etme_formu_route(device_id):
    device = session.query(Device).get(device_id)
    if not device:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    pdf_buffer = generate_pdf(device, "teslim_etme")
    return send_file(pdf_buffer, as_attachment=True, download_name=f"teslim_etme_{device_id}.pdf", mimetype='application/pdf')

@app.route("/devices/<int:device_id>/generate-teklif-formu", methods=["GET"])
@jwt_required()
def generate_teklif_formu_route(device_id):
    device = session.query(Device).get(device_id)
    if not device:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    pdf_buffer = generate_pdf(device, "teklif")
    return send_file(pdf_buffer, as_attachment=True, download_name=f"teklif_{device_id}.pdf", mimetype='application/pdf')

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
