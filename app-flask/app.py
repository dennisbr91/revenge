import os

from flask import Flask, request, jsonify, send_file, make_response
from pyrebase import pyrebase
from flask_socketio import SocketIO, emit, disconnect
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
from flask_login import LoginManager, login_user, login_required, current_user
from sqlalchemy import create_engine, PickleType
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from firebase import config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import pytz

app = Flask(__name__)
app.app_context().push()

login_manager = LoginManager()
login_manager.init_app(app)

app.config[
    'SECRET_KEY'] = '123456789646543213das0202as1d2a3s21s2da2s2154d65asda5s4d6a5s4da6sd4asd2a1'

app.config[
    'SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:MyHyperSecretPasswordForRootUserMysqlDB**.910214@mysql/chat-db'

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['SQLALCHEMY_POOL_RECYCLE'] = 3600
app.config['SQLALCHEMY_POOL_SIZE'] = 100
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)
migrate = Migrate(app, db)

socketio = SocketIO(app)

engine = create_engine(
    'mysql+mysqlconnector://root:MyHyperSecretPasswordForRootUserMysqlDB**.910214@mysql/chat-db')
Session = sessionmaker(bind=engine)
session = Session()

firebase = pyrebase.initialize_app(config)
auth = firebase.auth()
connected_clients = {}


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sub_id = db.Column(db.String(248))
    sender = db.Column(db.String(120))
    sender_id = db.Column(db.Integer)
    sender_name = db.Column(db.String(120))
    sender_image = db.Column(db.String(120))
    recipient = db.Column(db.String(120))
    recipient_id = db.Column(db.Integer)
    recipient_name = db.Column(db.String(120))
    recipient_image = db.Column(db.String(120))
    content = db.Column(db.String(500))
    type = db.Column(db.String(100))
    uris = db.Column(db.String(500))
    reaction = db.Column(db.String(120), default='')
    readed = db.Column(db.Boolean(), default=False)
    timestamp = db.Column(db.String(500), default=datetime.utcnow())


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255))
    fcm_token = db.Column(db.String(1024))
    is_active = db.Column(db.Boolean, default=True)

    def get_id(self):
        return str(self.id)

    @staticmethod
    def is_authenticated():
        return True


@login_manager.user_loader
def load_user(user_id):
    return session.get(User, user_id)


@app.route('/login', methods=['POST'])
def login():
    id_token = request.json['token']
    if request.method == 'POST':
        try:
            user_firebase = auth.get_account_info(id_token)
            user_email = user_firebase['users'][0]['email']
            user = User.query.filter_by(email=user_email).first()
            if user is not None:
                login_user(user, remember=True)
                response = {
                    "success": True,
                    "data": user.email
                }
                return make_response(jsonify(response), 200)
            else:
                user = User(
                    email=user_firebase['users'][0]['email'],
                    fcm_token=user_firebase['users'][0]['email']
                )
                db.session.add(user)
                db.session.commit()
                login_user(user, remember=True)
                response = {
                    "success": True,
                    "data": user.email
                }
                return make_response(jsonify(response), 200)
        except:
            response = {
                "success": False,
                "message": 'User not logged, token invalid'
            }
            return make_response(jsonify(response), 401)


@app.route('/download', methods=['GET'])
# @login_required
def Download_File():
    file = request.json['file']
    # file = '1910012759_PharOS_User_Guide.pdf'
    PATH = os.path.join('files', file)
    try:
        if os.path.exists(PATH):
            return send_file(PATH, as_attachment=True)
        else:
            response = {
                "success": False,
                "message": 'file not found'
            }
            return make_response(jsonify(response), 404)
    except Exception as e:
        response = {
            "success": False,
            "message": str(e)
        }
        return make_response(jsonify(response), 400)


@app.route('/upload', methods=['POST'])
# @login_required
def upload_file():
    print(f"esto es el upload: {current_user.email}")
    if request.method == 'POST':
        try:
            f = request.files['file']
            # extension = f.rsplit('.', 1)[1].lower()
            filename = secure_filename(f.filename)
            f.save(os.path.join('files', filename))
            response = {
                "success": True,
                "data": filename
            }
            return make_response(jsonify(response), 200)
        except Exception as e:
            response = {
                "success": False,
                "message": str(e)
            }
            return make_response(jsonify(response), 400)
        except RequestEntityTooLarge:
            response = {
                "success": False,
                "message": 'error uploading file, max 16 MB'
            }
            return make_response(jsonify(response), 400)
    else:
        response = {
            "success": False,
            "message": 'only accept POST method',
            "user": current_user.email
        }
        return make_response(jsonify(response), 400)


@socketio.on('connect')
def handle_connect():
    id_token = request.headers['token']
    try:
        user_firebase = auth.get_account_info(id_token)
        connected_clients[user_firebase['users'][0]['email']] = request.sid
        user_email = user_firebase['users'][0]['email']
        search_user = User.query.filter_by(email=user_email)
        if search_user.count() > 0:
            print('user exist')
        else:
            user = User(
                email=user_firebase['users'][0]['email'],
                fcm_token=user_firebase['users'][0]['email']
            )
            db.session.add(user)
            db.session.commit()
        recipient_sid = connected_clients.get(user_email)
        for_my = Message.query.filter_by(sender=user_email)
        for result in for_my:
            emit(
                'private_message',
                {
                    'message_id': result.id,
                    'sub_id': result.sub_id,
                    'message': result.content,
                    'recipient': result.recipient,
                    'recipient_id': result.recipient_id,
                    'recipient_name': result.recipient_name,
                    'recipient_image': result.recipient_image,
                    'sender': result.sender,
                    'sender_id': result.sender_id,
                    'sender_name': result.sender_name,
                    'sender_image': result.sender_image,
                    'type': result.type,
                    'uris': result.uris,
                    'reaction': result.reaction,
                    'readed': result.readed,
                    'timestamp': result.timestamp
                },
                room=recipient_sid,
                callback=readed
            )
        to_my = Message.query.filter_by(recipient=user_email)
        for result in to_my:
            emit(
                'private_message',
                {
                    'message_id': result.id,
                    'sub_id': result.sub_id,
                    'message': result.content,
                    'recipient': result.recipient,
                    'recipient_id': result.recipient_id,
                    'recipient_name': result.recipient_name,
                    'recipient_image': result.recipient_image,
                    'sender': result.sender,
                    'sender_id': result.sender_id,
                    'sender_name': result.sender_name,
                    'sender_image': result.sender_image,
                    'uris': result.uris,
                    'type': result.type,
                    'reaction': result.reaction,
                    'readed': result.readed,
                    'timestamp': result.timestamp
                },
                room=recipient_sid,
                callback=readed
            )
        for uid, sid in connected_clients.items():
            print(f'esto es el online: {uid}')
            emit(
                'users_online',
                {
                    'email': uid
                },
                broadcast=True
            )
    except:
        print('token invalid')
        disconnect()


@socketio.on('disconnect')
def handle_disconnect():
    for uid, sid in connected_clients.items():
        if sid == request.sid:
            del connected_clients[uid]
            print(f'Esto es el email del usuario desconectado: {uid}')
            emit(
                'users_offline',
                {
                    'email': uid
                },
                broadcast=True
            )
            break


@socketio.on('imageUpdate')
def handle_imageUpdate(data):
    sender = data['sender']
    sender_id = data['sender_id']
    to_notify = data['emails']
    id_list = to_notify.split(",")
    for item in id_list:
        recipient_sid = connected_clients.get(item)
        emit(
            'imageUpdate',
            {
                'email': sender,
                'user_id': sender_id
            },
            room=recipient_sid,
        )


@socketio.on('status')
def handle_status(data):
    recipient_sid = connected_clients.get(data['sender'])
    if isinstance(data, dict):
        for uid, sid in connected_clients.items():
            if uid == data['email']:
                print(f'el usuario esta conectado: {uid}')
                emit(
                    'status',
                    {
                        'connected': True,
                        'email': data['email']
                    },
                    room=recipient_sid,
                )
    else:
        emit(
            'alert',
            {
                'message': 'Data must be a DICT'
            },
            room=recipient_sid,
        )


@socketio.on('delete')
def handle_disconnect(data):
    if isinstance(data, dict):
        message_delete = data['message_id']
        id_list = message_delete.split(",")
        for id_item in id_list:
            Message.query.filter_by(
                id=id_item
            ).delete()
        db.session.commit()


@socketio.on('references')
def handle_references(data):
    recipient_sid = connected_clients.get(data['recipient'])
    sender_sid = connected_clients.get(data['sender'])
    result = Message.query.filter_by(
        id=data['id_message']
    ).first()
    if isinstance(data, dict):
        uris_string = None
        if 'uris' in data:
            uris = data['uris']
            uris_string = ','.join(uris)

        message = Message(
            sub_id=data['sub_id'],
            sender=data['sender'],
            sender_id=data['sender_id'],
            sender_name=data['sender_name'],
            sender_image=data['sender_image'],
            recipient=data['recipient'],
            recipient_id=data['recipient_id'],
            recipient_name=data['recipient_name'],
            recipient_image=data['recipient_image'],
            content=data['message'],
            uris=uris_string,
            type=data['type'],
            timestamp=datetime.utcnow(),
        )
        db.session.add(message)
        db.session.commit()
        emit(
            'private_message',
            {
                'message_id': message.id,
                'sub_id': message.sub_id,
                'recipient': message.recipient,
                'recipient_id': message.recipient_id,
                'recipient_name': message.recipient_name,
                'recipient_image': message.recipient_image,
                'sender': message.sender,
                'sender_id': message.sender_id,
                'sender_name': message.sender_name,
                'sender_image': message.sender_image,
                'type': message.type,
                'uris': message.uris,
                'readed': message.readed,
                'message': message.content,
                'message_referenced': {
                    'ref_id': result.id,
                    'ref_content': result.content,
                    'ref_type': result.type,
                },
                'timestamp': message.timestamp
            },
            room=recipient_sid,
            callback=readed
        )
        emit(
            'private_message',
            {
                'message_id': message.id,
                'sub_id': message.sub_id,
                'recipient': message.recipient,
                'recipient_id': message.recipient_id,
                'recipient_name': message.recipient_name,
                'recipient_image': message.recipient_image,
                'sender': message.sender,
                'sender_id': message.sender_id,
                'sender_name': message.sender_name,
                'sender_image': message.sender_image,
                'type': message.type,
                'uris': message.uris,
                'readed': message.readed,
                'message': message.content,
                'message_referenced': {
                    'ref_id': result.id,
                    'ref_content': result.content,
                    'ref_type': result.type,
                },
                'timestamp': message.timestamp
            },
            room=sender_sid,
            callback=nothing
        )
    else:
        print(f'data must be a dict: {type(data)}')
        emit(
            'alert',
            {
                'message': f'data must be a dict: {type(data)}',
                'sender': 'SocketIO Server',
            })


@socketio.on('file')
def handle_file(data):
    recipient_sid = connected_clients.get(data['recipient'])
    emit(
        'private_message',
        {
            'message': data['message'],
            'sender': data['sender'],
            'file': data['file']
        },
        room=recipient_sid
    )


@socketio.on('private_message')
def handle_private_message(data):
    if isinstance(data, dict):
        recipient_sid = connected_clients.get(data['recipient'])
        sender_sid = connected_clients.get(data['sender'])
        print(data)
        uris_string = None
        reaction = None

        if 'uris' in data:
            uris = data['uris']
            uris_string = ','.join(uris)
        if 'reaction' in data:
            reaction = data['reaction']

        message = Message(
            sub_id=data['sub_id'],
            sender=data['sender'],
            sender_id=data['sender_id'],
            sender_name=data['sender_name'],
            sender_image=data['sender_image'],
            recipient=data['recipient'],
            recipient_id=data['recipient_id'],
            recipient_name=data['recipient_name'],
            recipient_image=data['recipient_image'],
            type=data['type'],
            content=data['message'],
            uris=uris_string,
            reaction=reaction,
            timestamp=datetime.utcnow(),
        )
        db.session.add(message)
        db.session.commit()
        emit(
            'private_message',
            {
                'message_id': message.id,
                'sub_id': message.sub_id,
                'recipient': message.recipient,
                'recipient_id': message.recipient_id,
                'recipient_name': message.recipient_name,
                'recipient_image': message.recipient_image,
                'sender': message.sender,
                'sender_id': message.sender_id,
                'sender_name': message.sender_name,
                'sender_image': message.sender_image,
                'type': message.type,
                'uris': message.uris,
                'reaction': message.reaction,
                'readed': message.readed,
                'message': message.content,
                'timestamp': message.timestamp
            },
            room=recipient_sid,
            callback=readed
        )
        emit(
            'private_message',
            {
                'message_id': message.id,
                'sub_id': message.sub_id,
                'recipient': message.recipient,
                'recipient_id': message.recipient_id,
                'recipient_name': message.recipient_name,
                'recipient_image': message.recipient_image,
                'sender': message.sender,
                'sender_id': message.sender_id,
                'sender_name': message.sender_name,
                'sender_image': message.sender_image,
                'type': message.type,
                'uris': message.uris,
                'reaction': message.reaction,
                'readed': message.readed,
                'message': message.content,
                'timestamp': message.timestamp
            },
            room=sender_sid,
            callback=nothing
        )
    else:
        emit(
            'alert',
            {
                'message': f'data must be a dict: {type(data)}',
                'sender': 'SocketIO Server',
            })


@socketio.on('reaction')
def handle_reaction(data):
    if isinstance(data, dict):
        print(f'esto es lo que llega del reaction: {data}')
        recipient_sid = connected_clients.get(data['recipient'])
        sender_sid = connected_clients.get(data['sender'])
        result = Message.query.filter_by(
            id=data['id_message']
        ).first()
        result.reaction = str(data['reaction'])
        db.session.commit()
        emit(
            'reaction',
            {
                'reaction': data['reaction'],
                'message_id': result.id
            },
            room=recipient_sid
        )
        emit(
            'reaction',
            {
                'reaction': data['reaction'],
                'message_id': result.id
            },
            room=sender_sid
        )
    else:
        emit(
            'alert',
            {
                'message': f'data must be a dict: {type(data)}',
                'sender': 'SocketIO Server',
            })


def nothing(data):
    print(f'callback to sender: {data}')


def readed(data):
    result = Message.query.filter_by(id=data['message_id']).first()
    result.readed = True
    db.session.commit()


if __name__ == '__main__':
    db.create_all()
    socketio.run(app, debug=True, host='0.0.0.0', port=6001)
