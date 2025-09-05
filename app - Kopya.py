from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from sqlalchemy import create_engine, Column, Integer, String, Float, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt, JWTManager
import os

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
    role = Column(String, nullable=False, default='user') # 'admin' or 'user'

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
    # YENİ EKLENEN ALAN
    teklif_durumu = Column(String, default='Teklif Bekliyor') # Teklif Bekliyor, Teklif Verildi, Onaylandı, Reddedildi, Fatura Edildi

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

# --- Helper to convert device object to dict ---
def device_to_dict(d):
    return {
        "id": d.id, "marka": d.marka, "model": d.model, "seri_no": d.seri_no,
        "kurum": d.kurum, "alinma_tarihi": d.alinma_tarihi, "aksesuar": d.aksesuar,
        "ariza": d.ariza, "tespit": d.tespit, "resim1": d.resim1, "resim2": d.resim2,
        "resim3": d.resim3, "onarim_resim1": d.onarim_resim1, "onarim_resim2": d.onarim_resim2,
        "onarim_resim3": d.onarim_resim3, "geri_teslim_tarihi": d.geri_teslim_tarihi,
        "personel": d.personel, "maliyet": d.maliyet, "servis_ucreti": d.servis_ucreti,
        "status": d.status, "completed_by": d.completed_by,
        "teklif_durumu": d.teklif_durumu # YENİ ALANI EKLE
    }

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

# --- User Management Routes (Admin Only) ---
def is_admin():
    return get_jwt().get("role") == "admin"

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
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")

    if not username or not password:
        return jsonify({"error": "Kullanıcı adı ve şifre gereklidir"}), 400
    
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
    
    user = session.query(User).filter(User.id == user_id).first()
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
    if query and len(query) >= 3:
        search_term = f"%{query}%"
        devices_query = devices_query.filter(
            (Device.marka.ilike(search_term)) | (Device.model.ilike(search_term)) |
            (Device.seri_no.ilike(search_term)) | (Device.kurum.ilike(search_term)) |
            (Device.ariza.ilike(search_term)) | (Device.tespit.ilike(search_term))
        )
    devices = devices_query.order_by(Device.id.desc()).all()
    return jsonify([device_to_dict(d) for d in devices])

@app.route("/devices", methods=["POST"])
@jwt_required()
def add_device():
    data = request.json
    # remove fields that are not in the model to prevent errors
    data.pop('id', None) 
    data.pop('status', None)
    data.pop('completed_by', None)
    new_device = Device(**data)
    session.add(new_device)
    session.commit()
    return jsonify({"message": "Cihaz başarıyla eklendi", "id": new_device.id}), 201


@app.route("/devices/<int:device_id>", methods=["GET"])
@jwt_required()
def get_device(device_id):
    device = session.query(Device).filter(Device.id == device_id).first()
    if not device:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    return jsonify(device_to_dict(device))

@app.route("/devices/<int:device_id>", methods=["PUT"])
@jwt_required()
def update_device(device_id):
    device = session.query(Device).filter(Device.id == device_id).first()
    if not device:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
        
    if device.status == 'completed' and not is_admin():
        return jsonify({"error": "Tamamlanmış bir kayıt kullanıcı tarafından değiştirilemez"}), 403
        
    data = request.json
    for key, value in data.items():
        setattr(device, key, value)
    session.commit()
    return jsonify({"message": "Cihaz başarıyla güncellendi"})

@app.route("/devices/<int:device_id>", methods=["DELETE"])
@jwt_required()
def delete_device(device_id):
    if not is_admin():
        return jsonify({"error": "Silme işlemi için yetkiniz yok"}), 403

    device = session.query(Device).filter(Device.id == device_id).first()
    if not device:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    session.delete(device)
    session.commit()
    return jsonify({"message": "Cihaz silindi"})

@app.route("/devices/<int:device_id>/complete", methods=["POST"])
@jwt_required()
def complete_device(device_id):
    device = session.query(Device).filter(Device.id == device_id).first()
    if not device:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
        
    device.status = 'completed'
    device.completed_by = get_jwt_identity()
    session.commit()
    return jsonify({"message": "Cihaz tamamlandı olarak işaretlendi"})

# --- Image Upload Routes ---
@app.route("/devices/<int:device_id>/upload", methods=["POST"])
@jwt_required()
def upload_image(device_id):
    device = session.query(Device).filter(Device.id == device_id).first()
    if not device:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    
    if device.status == 'completed' and not is_admin():
        return jsonify({"error": "Tamamlanmış bir kayda resim eklenemez"}), 403

    file_index = request.form.get("index", "1")
    file = request.files.get("file")
    if file:
        filename = f"{device_id}_{file_index}_{file.filename}"
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

# --- YENİ RAPOR ENDPOINT'İ ---
@app.route("/report", methods=["GET"])
@jwt_required()
def get_report():
    if not is_admin():
        return jsonify({"error": "Yetkiniz yok"}), 403

    try:
        devices = session.query(Device).all()
        
        report_data = {
            "total_devices": len(devices),
            "status_counts": {
                "open": 0,
                "completed": 0
            },
            "offer_status_counts": {
                "Teklif Bekliyor": 0,
                "Teklif Verildi": 0,
                "Onaylandı": 0,
                "Reddedildi": 0,
                "Fatura Edildi": 0
            },
            "financials": {
                "total_cost": 0.0,
                "total_fee": 0.0,
                "net_income": 0.0
            }
        }

        total_cost = 0.0
        total_fee = 0.0

        for device in devices:
            # Status counts
            if device.status in report_data["status_counts"]:
                report_data["status_counts"][device.status] += 1
            
            # Offer status counts
            if device.teklif_durumu in report_data["offer_status_counts"]:
                report_data["offer_status_counts"][device.teklif_durumu] += 1

            # Financials
            total_cost += device.maliyet or 0.0
            total_fee += device.servis_ucreti or 0.0

        report_data["financials"]["total_cost"] = total_cost
        report_data["financials"]["total_fee"] = total_fee
        report_data["financials"]["net_income"] = total_fee - total_cost

        return jsonify(report_data)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    # Windows masaüstü uygulaması için 127.0.0.1 yeterlidir.
    # Mobil emülatör veya gerçek telefon ile test edecekseniz host='0.0.0.0' kullanın.
    app.run(host='127.0.0.1', port=5000, debug=True)
