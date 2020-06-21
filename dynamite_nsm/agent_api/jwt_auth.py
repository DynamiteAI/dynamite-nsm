from flask_security.utils import verify_password
from flask_security import SQLAlchemySessionUserDatastore

from dynamite_nsm.agent_api import models
from dynamite_nsm.agent_api.database import db_session

user_datastore = SQLAlchemySessionUserDatastore(db_session, models.User, models.Role)


def auth_handler(username, password):
    user = user_datastore.find_user(email=username)
    if username == user.email and verify_password(password, user.password):
        return user


def load_user(payload):
    user = user_datastore.find_user(id=payload['identity'])
    return user

