from datetime import timedelta, datetime
from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, create_refresh_token, get_jwt
from jwt.exceptions import ExpiredSignatureError

app = Flask(__name__)
api = Api(app)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(seconds=24)  # e.g., 24 hours for access tokens
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(minutes=1)  # e.g., 7 days for refresh tokens
app.config['JWT_SECRET_KEY'] = '123456789'  # replace with a strong secret key

db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)


@jwt.expired_token_loader
def my_expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'status': 401,
        'msg': 'The token has expired'
    }), 401


# You can also add more error handlers if needed:
@jwt.invalid_token_loader
def my_invalid_token_callback(error):
    return jsonify({
        'status': 422,  # you can choose your preferred status code
        'msg': 'Invalid token'
    }), 422


@jwt.unauthorized_loader
def my_unauthorized_response(callback):
    return jsonify({
        'status': 401,
        'msg': 'Missing Authorization Header'
    }), 401


@jwt.token_in_blocklist_loader
def check_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    token = TokenBlacklist.query.filter_by(jti=jti).first()
    return token and token.revoked


def remove_expired_tokens():
    now = datetime.utcnow()
    expired = TokenBlacklist.query.filter(TokenBlacklist.expires < now).all()
    for token in expired:
        db.session.delete(token)
    db.session.commit()


class TokenBlacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120), nullable=False)  # JTI is the unique identifier for a JWT
    token_type = db.Column(db.String(10), nullable=False)
    user_identity = db.Column(db.String(50), nullable=False)
    revoked = db.Column(db.Boolean, nullable=False, default=True)
    expires = db.Column(db.DateTime, nullable=False)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    position = db.Column(db.String(80), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class SignUp(Resource):
    def post(self):
        data = request.get_json()
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

        new_user = User(username=data['username'], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return {"message": "User created successfully."}, 201


# class RefreshToken(Resource):
#     @jwt_required(refresh=True)
#     def post(self):
#         current_user = get_jwt_identity()
#         new_access_token = create_access_token(identity=current_user)
#         new_refresh_token = create_refresh_token(identity=current_user)
#         return {"access_token": new_access_token, "refresh_token": new_refresh_token}, 200
#         # return jsonify(access_token=new_access_token, refresh_token=new_refresh_token), 200

class RefreshToken(Resource):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()

        # Get the old token's jti
        old_token_jti = get_jwt()['jti']

        # Add old token to the blacklist
        old_token = TokenBlacklist(
            jti=old_token_jti,
            token_type='refresh',
            user_identity=str(current_user),
            expires=datetime.utcnow() + app.config['JWT_REFRESH_TOKEN_EXPIRES']
        )
        db.session.add(old_token)
        db.session.commit()

        # Generate new tokens
        new_access_token = create_access_token(identity=current_user)
        new_refresh_token = create_refresh_token(identity=current_user)

        # Add the new refresh token to the database as non-revoked
        new_refresh_token_entry = TokenBlacklist(
            jti=new_refresh_token,
            token_type='refresh',
            user_identity=str(current_user),
            revoked=False,
            expires=datetime.utcnow() + app.config['JWT_REFRESH_TOKEN_EXPIRES']
        )
        db.session.add(new_refresh_token_entry)
        db.session.commit()

        return {"access_token": new_access_token, "refresh_token": new_refresh_token}, 200


class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(username=data['username']).first()

        if user and bcrypt.check_password_hash(user.password, data['password']):
            access_token = create_access_token(identity=user.id)
            refresh_token = create_refresh_token(identity=user.id)
            # Add the new refresh token to the database as non-revoked
            refresh_token_entry = TokenBlacklist(
                jti=refresh_token,
                token_type='refresh',
                user_identity=str(user.id),
                revoked=False,
                expires=datetime.utcnow() + app.config['JWT_REFRESH_TOKEN_EXPIRES']
            )
            db.session.add(refresh_token_entry)
            db.session.commit()

            return {"message": "Login successful.", "access_token": access_token, "refresh_token": refresh_token, "user_id": user.id}, 200
        else:
            return {"message": "Invalid credentials."}, 401


class EmployeeResource(Resource):

    @jwt_required()
    def get(self, user_id):
        try:
            user_id = get_jwt_identity()
            user = User.query.get_or_404(user_id)
            employees = Employee.query.filter_by(user_id=user.id).all()
            return {"employees": [{"id": emp.id, "name": emp.name, "position": emp.position} for emp in employees]}, 200
        except ExpiredSignatureError as error:
            print(f'Unable to decode the token, error: {error}')
            return {"message": "Token Expire."}, 401

    @jwt_required()
    def post(self, user_id):
        user_id = get_jwt_identity()
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        new_employee = Employee(name=data['name'], position=data['position'], user_id=user.id)
        db.session.add(new_employee)
        db.session.commit()
        return {"message": "Employee added successfully.",
                "employee": {"id": new_employee.id, "name": new_employee.name, "position": new_employee.position}}, 201

    @jwt_required()
    def put(self, user_id, emp_id):
        user_id = get_jwt_identity()
        user = User.query.get_or_404(user_id)
        employee = Employee.query.get_or_404(emp_id)
        if employee.user_id != user.id:
            return {"error": "Permission denied"}, 403
        data = request.get_json()
        employee.name = data['name']
        employee.position = data['position']
        db.session.commit()
        return {"message": "Employee updated successfully.",
                "employee": {"id": employee.id, "name": employee.name, "position": employee.position}}, 200

    @jwt_required()
    def delete(self, user_id, emp_id):
        user_id = get_jwt_identity()
        user = User.query.get_or_404(user_id)
        employee = Employee.query.get_or_404(emp_id)
        if employee.user_id != user.id:
            return {"error": "Permission denied"}, 403
        db.session.delete(employee)
        db.session.commit()
        return {"message": "Employee deleted successfully."}, 200


api.add_resource(EmployeeResource, '/user/<int:user_id>/employees', '/user/<int:user_id>/employee/<int:emp_id>')

api.add_resource(SignUp, '/signup')
api.add_resource(Login, '/login')
api.add_resource(RefreshToken, '/refresh_token')


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
