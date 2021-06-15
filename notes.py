from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy
from werkzeug.exceptions import HTTPException
import os
import hashlib
import jwt
from functools import wraps
from flask_cors import CORS

# This Project has Turkish Comments Lines. If you use this project and you dont know turkish, get learn or open translate.
# If you want divide the projects into parts, you use blueprint package.

app = Flask(__name__)  # Flask uygulaması oluştur.
CORS(app)
app.config['SECRET_KEY'] = "my_security_key_for_jwt"
# Projenin olduğu klasörün(klasör dahil) dosya yolunu alır.
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(
        basedir, 'ploud.db')  # Birleştirme yapar. sqlite:////basedir/ploud.db şeklinde.
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)  # Veri Tabanını uygulamaya entegre ediyor.
# Marshmallow kütüphanesi ile temiz bir şekilde veri tabanından aldığımız dataları serialize ediyoruz.
ma = Marshmallow(app)


# token konrol işlemini yapan bir decorator oluşturuyoruz.
def token_required(func):
    @wraps(func)  # decorator oluşturmada kullanılıyor.
    def wrapped(*args, **kwargs):
        # Authorization içerisinde token 'Bearer token' şeklinde tutuluyor.
        if 'Authorization' in request.headers:
            bearer_token = request.headers['Authorization']
            token = bearer_token[7:len(bearer_token)]
        if not token:
            return jsonify({'error': 'Token bulunmamaktadır!'}), 401
        try:
            data = jwt.decode(
                token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({'error': 'Geçersiz token'}), 403
        return func(*args, **kwargs)
    return wrapped


@app.route("/note", methods=["POST"])
@token_required
def add_note():
    title = request.json['title']
    description = request.json['description']
    user_id = request.json['user_id']
    note = Note(title, description, user_id)
    db.session.add(note)
    db.session.commit()
    return jsonify({"message": "Yeni Not Başarılı Bir Şekilde Eklenmiştir."}), 201


@app.route("/note/<int:id>", methods=["DELETE"])
@token_required
def delete_note(id):
    # Alternatif olarak Note.query.filter_by(id = id).first()
    note = Note.query.get(id)
    db.session.delete(note)
    # Yapılan DB işlemlerini veri tabanına yansıtır. Silme, Ekleme ve güncelleme işlemleri ORM'lerde genellikle önce belleğe alınır.
    db.session.commit()
    return jsonify({"message": note.title+" Başlıklı Not Başarılı Bir Şekilde Silinmiştir."})


@app.route("/note/<int:id>", methods=["PUT"])
@token_required
def update_note(id):
    note = Note.query.get(id)
    title = request.json['Bearer']
    description = request.json['description']
    user_id = request.json['user_id']
    note.title = title
    note.description = description
    note.user_id = user_id
    db.session.commit()
    return note_schema.jsonify(note)


@app.route("/note/<int:user_id>", methods=["GET"])
@token_required
def get_user_note(user_id):
    notes = Note.query.filter_by(user_id=user_id).all()
    result = notes_schema.dump(notes)
    return jsonify({"data": result}), 200


@app.route("/user", methods=["POST"])
def add_user():
    first_name = request.json['first_name']
    last_name = request.json['last_name']
    email = request.json['email']
    password = request.json['password']
    db_user = User.query.filter_by(email=email).first()
    if db_user is not None:
        return jsonify({'error': 'Daha önce bu mail adresi ile üyelik yapılmıştır.'}), 400
    pw_hash = hashlib.md5(password.encode())
    user = User(first_name, last_name, email, pw_hash.hexdigest())
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Yeni kullanıcı başarılı bir şekilde oluşturulmuştur."}), 201


@app.route("/login", methods=['POST'])
def login():
    email = request.json['email']
    password = request.json['password']
    pw_hash = hashlib.md5(password.encode())
    pw_hash_str = pw_hash.hexdigest()
    user = User.query.filter_by(email=email, password=pw_hash_str).first()
    print(user)
    if user is not None:
        token = jwt.encode({'user_id': user.id,
                            'exp':  datetime.utcnow()+timedelta(minutes=10),
                            'iat': datetime.utcnow()}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token, 'user_id': user.id, 'user_first_name': user.first_name, 'user_last_name': user.last_name, 'user_email': user.email})
    return jsonify(error='Lütfen girdiğiniz bilgileri kontrol ediniz!'), 400


# Global Exception Handler metodu
@app.errorhandler(Exception)
def handle_error(e):
    code = 500
    if isinstance(e, HTTPException):
        code = e.code
    return jsonify({"error": str(e)}), code


# Veri Tabanında Note isimli bir tablo oluşturmada bu sınıf kullanılıyor.
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(40), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    # One to Many olan ilişkide Many ilişkisi Foreign Key ile oluşturulur.
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, title, description, user_id):
        self.title = title
        self.description = description
        self.user_id = user_id


# Veri Tabanında User isimli bir tablo oluşturmada kullanılır.
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(25), nullable=False)
    last_name = db.Column(db.String(25), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_delete = db.Column(db.Boolean, default=False, nullable=False)
    # One to Many ilişki kurmada One olan kısmı belirtmede kullanılır.
    notes = db.relationship('Note', backref='user', lazy=True)

    # Sınıftan örnek alırken örnek üzerinden parantezler arasında değer girmemize yarayan constructor metodu.
    def __init__(self, first_name, last_name, email, password, is_active=True, is_delete=False):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password = password
        self.is_active = is_active
        self.is_delete = is_delete


# Object serialize etmek için kullanılıyor.
class NoteSchema(ma.Schema):
    class Meta:
        fields = ('id', 'title', 'description', 'user_id')


# Tek veri içeren object serialize etmede kullanılır.
note_schema = NoteSchema()
# Liste şeklinde Obje seialize etmede kullanılır.
notes_schema = NoteSchema(many=True)


class UserSchema(ma.Schema):
    class Meta:
        fields = ("id", "first_name", "last_name",
                  "email", "is_active", "is_delete")


user_schema = UserSchema()
users_schema = UserSchema(many=True)


if __name__ == '__main__':
    # Proje ayağa kalkarken veri tabanını oluşturur. Veri Tabanı daha önceden oluşmuş ise çalışmaz.
    db.create_all()
    app.run(debug=True)  # Projeyi Debug modda ayağa kaldırır.
