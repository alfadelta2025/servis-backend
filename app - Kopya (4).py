from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from sqlalchemy import create_engine, Column, Integer, String, Float, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt, JWTManager
import os
from datetime import datetime
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
import io

# --- App Configuration ---
app = Flask(__name__)
CORS(app)

# --- JWT Configuration ---
app.config["JWT_SECRET_KEY"] = "bu-anahtari-mutlaka-degistirin" # Change this to a strong secret
jwt = JWTManager(app)

# --- File Upload Configuration ---
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Database Configuration ---
engine = create_engine("sqlite:///servis.db", echo=False)
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)
session = SessionLocal()

# --- Database Models ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default='user') # 'admin', 'user', or 'customer'

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
    status = Column(String, default='open') # 'open' or 'completed'
    completed_by = Column(String)
    teklif_durumu = Column(String, default='Teklif Bekliyor')
    iletisim_kisi = Column(String)
    iletisim_tel = Column(String)
    # YENİ EKLENEN ALAN: Müşteri tarafından gönderilen kayıtları takip etmek için
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

# --- Auth Helper Functions ---
def get_current_user_role():
    return get_jwt().get("role")

def get_current_user_identity():
    return get_jwt_identity()

def is_admin():
    return get_current_user_role() == "admin"

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
        # ROL BİLGİSİ TOKEN'A EKLENİYOR
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
    # 'customer' rolü artık geçerli bir rol
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

# --- Device Routes ---
@app.route("/devices", methods=["GET"])
@jwt_required()
def get_devices():
    query = request.args.get("q", "")
    devices_query = session.query(Device)
    
    # GÜNCELLEME: Eğer kullanıcı 'customer' ise, sadece kendi kayıtlarını göster
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

    # GÜNCELLEME: Müşteri sadece belirli alanları gönderebilir
    if user_role == 'customer':
        allowed_fields = ['marka', 'model', 'kurum', 'iletisim_kisi', 'ariza']
        filtered_data = {key: data[key] for key in allowed_fields if key in data}
        new_device = Device(**filtered_data)
    else:
        # Admin ve user tüm alanları gönderebilir
        data.pop('id', None)
        data.pop('status', None)
        data.pop('completed_by', None)
        new_device = Device(**data)

    # GÜNCELLEME: Kaydı kimin oluşturduğunu ekle
    new_device.submitted_by = current_user
    if not new_device.alinma_tarihi: # Eğer alınma tarihi boşsa bugünü ata
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
    # GÜNCELLEME: Müşterinin başkasının kaydını görmesini engelle
    if get_current_user_role() == 'customer' and device.submitted_by != get_current_user_identity():
        return jsonify({"error": "Yetkiniz yok"}), 403
    return jsonify(device_to_dict(device))

@app.route("/devices/<int:device_id>", methods=["PUT"])
@jwt_required()
def update_device(device_id):
    # GÜNCELLEME: Müşterinin kayıt güncellemesini engelle
    if get_current_user_role() == 'customer':
        return jsonify({"error": "Güncelleme yetkiniz yok"}), 403

    device = session.query(Device).get(device_id)
    if not device:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    if device.status == 'completed' and not is_admin():
        return jsonify({"error": "Tamamlanmış bir kayıt kullanıcı tarafından değiştirilemez"}), 403
    
    data = request.json
    for key, value in data.items():
        if hasattr(device, key):
            setattr(device, key, value)
    session.commit()
    return jsonify({"message": "Cihaz başarıyla güncellendi"})

@app.route("/devices/<int:device_id>", methods=["DELETE"])
@jwt_required()
def delete_device(device_id):
    if not is_admin():
        return jsonify({"error": "Silme işlemi için yetkiniz yok"}), 403
    device = session.query(Device).get(device_id)
    if not device:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    session.delete(device)
    session.commit()
    return jsonify({"message": "Cihaz silindi"})

@app.route("/devices/<int:device_id>/complete", methods=["POST"])
@jwt_required()
def complete_device(device_id):
    if get_current_user_role() == 'customer':
        return jsonify({"error": "Yetkiniz yok"}), 403
    device = session.query(Device).get(device_id)
    if not device:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    device.status = 'completed'
    device.completed_by = get_current_user_identity()
    session.commit()
    return jsonify({"message": "Cihaz tamamlandı olarak işaretlendi"})

# --- Image Upload Route ---
@app.route("/devices/<int:device_id>/upload", methods=["POST"])
@jwt_required()
def upload_image(device_id):
    if get_current_user_role() == 'customer':
        return jsonify({"error": "Resim yükleme yetkiniz yok"}), 403
        
    device = session.query(Device).get(device_id)
    if not device:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    if device.status == 'completed' and not is_admin():
        return jsonify({"error": "Tamamlanmış bir kayda resim eklenemez"}), 403
    file_index = request.form.get("index", "1")
    file = request.files.get("file")
    if file:
        filename = f"{device_id}_{file_index}_{datetime.now().timestamp()}_{file.filename}"
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        column_map = {"1": "resim1", "2": "resim2", "3": "resim3",
                      "4": "onarim_resim1", "5": "onarim_resim2", "6": "onarim_resim3"}
        if file_index in column_map:
            setattr(device, column_map[file_index], filepath)
        session.commit()
        return jsonify({"message": "Resim yüklendi", "filepath": filepath})
    return jsonify({"error": "Dosya bulunamadı"}), 400

@app.route("/uploads/<filename>")
def get_uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# --- PDF Generation Helper (No changes needed here) ---
def generate_pdf(device, form_type):
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    titles = {
        "teslim_alma": "TEKNİK SERVİS TESLİM ALMA FORMU",
        "teslim_etme": "TEKNİK SERVİS TESLİM ETME FORMU",
        "teklif": "TEKNİK SERVİS TEKLİF FORMU"
    }
    
    p.setFont("Helvetica-Bold", 16)
    p.drawString(100, height - 100, titles.get(form_type, "SERVİS FORMU"))
    p.line(100, height - 105, width - 100, height - 105)

    p.setFont("Helvetica", 12)
    y = height - 140
    
    info = [
        f"Marka/Model: {device.marka or ''} {device.model or ''}",
        f"Seri No: {device.seri_no or ''}",
        f"Kurum: {device.kurum or ''}",
        f"İletişim Kişisi: {device.iletisim_kisi or ''}",
        f"Telefon: {device.iletisim_tel or ''}",
        f"Alınma Tarihi: {device.alinma_tarihi or ''}",
    ]
    if form_type == "teslim_alma":
        info.append(f"Aksesuarlar: {device.aksesuar or ''}")
    if form_type == "teslim_etme":
        info.append(f"Geri Teslim Tarihi: {device.geri_teslim_tarihi or datetime.now().strftime('%d/%m/%Y')}")

    for line in info:
        p.drawString(100, y, line)
        y -= 25

    def draw_text_block(x, start_y, text, title):
        p.drawString(x, start_y, title)
        start_y -= 20
        lines = [text[i:i+70] for i in range(0, len(text or ""), 70)] if text else ["-"]
        for line in lines[:5]:
            p.drawString(x + 20, start_y, line)
            start_y -= 20
        return start_y - 10
    
    if form_type in ["teslim_alma", "teklif"]:
        y = draw_text_block(100, y, device.ariza, "Arıza Açıklaması:")
    
    if form_type in ["teslim_etme", "teklif"]:
        y = draw_text_block(100, y, device.tespit, "Yapılan İşlemler / Tespit ve Öneriler:")
    
    if form_type in ["teslim_etme", "teklif"]:
        p.setFont("Helvetica-Bold", 14)
        p.drawString(100, y, "ÜCRETLENDİRME")
        y -= 30
        p.setFont("Helvetica", 12)
        p.drawString(100, y, f"Maliyet: {device.maliyet or 0:.2f} TL")
        y -= 25
        p.drawString(100, y, f"Servis Ücreti: {device.servis_ucreti or 0:.2f} TL")
        y -= 25
        p.drawString(100, y, f"Toplam: {(device.maliyet or 0) + (device.servis_ucreti or 0):.2f} TL")
        y -= 30

    if form_type == "teklif":
        p.drawString(100, y, f"Teklif Durumu: {device.teklif_durumu or 'Teklif Bekliyor'}")
        y-= 30

    p.drawString(100, y, "Teslim Alan: _________________________")
    y -= 30
    p.drawString(100, y, "Teslim Eden: _________________________")
    y -= 30
    p.drawString(100, y, f"Tarih: {datetime.now().strftime('%d/%m/%Y')}")

    p.showPage()
    p.save()
    buffer.seek(0)
    return buffer

# --- PDF Generation Endpoints (No changes needed) ---
@app.route("/devices/<int:device_id>/generate-teslim-alma-formu", methods=["GET"])
@jwt_required()
def generate_teslim_alma_formu_route(device_id):
    device = session.query(Device).get(device_id)
    if not device: return jsonify({"error": "Cihaz bulunamadı"}), 404
    pdf_buffer = generate_pdf(device, "teslim_alma")
    return send_file(pdf_buffer, as_attachment=True, download_name=f"teslim_alma_{device_id}.pdf", mimetype='application/pdf')

@app.route("/devices/<int:device_id>/generate-teslim-etme-formu", methods=["GET"])
@jwt_required()
def generate_teslim_etme_formu_route(device_id):
    device = session.query(Device).get(device_id)
    if not device: return jsonify({"error": "Cihaz bulunamadı"}), 404
    pdf_buffer = generate_pdf(device, "teslim_etme")
    return send_file(pdf_buffer, as_attachment=True, download_name=f"teslim_etme_{device_id}.pdf", mimetype='application/pdf')

@app.route("/devices/<int:device_id>/generate-teklif-formu", methods=["GET"])
@jwt_required()
def generate_teklif_formu_route(device_id):
    device = session.query(Device).get(device_id)
    if not device: return jsonify({"error": "Cihaz bulunamadı"}), 404
    pdf_buffer = generate_pdf(device, "teklif")
    return send_file(pdf_buffer, as_attachment=True, download_name=f"teklif_{device_id}.pdf", mimetype='application/pdf')


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000, debug=True)
