import hashlib
from datetime import datetime

from flask_security import Security, SQLAlchemySessionUserDatastore

from dynamite_nsm import utilities
from dynamite_nsm.agent_api import models
from dynamite_nsm.agent_api.database import db_session, init_db


def create_default_user_and_roles(flask_app):
    user_datastore = SQLAlchemySessionUserDatastore(db_session, models.User, models.Role)
    Security(flask_app, user_datastore)
    init_db()
    temp_admin_user, temp_admin_role = None, None
    managerd_admin_user, admin_role = None, None

    if not user_datastore.find_user(email='admin@dynamite.local'):
        # We don't need to create a temporary admin except on the first initialization1
        if not user_datastore.find_role('admin'):
            temp_admin_user = user_datastore.create_user(email='admin@dynamite.local', username='admin',
                                                         password='changeme')

            db_session.commit()
            managerd_admin_user = user_datastore.create_user(email='managerd@dynamite.local', username='managerd',
                                                             password=hashlib.sha512(
                                                                 (
                                                                         str(utilities.get_default_agent_tag()) +
                                                                         str(utilities.get_cpu_core_count()) +
                                                                         str(utilities.get_memory_available_bytes()) +
                                                                         str(datetime.utcnow().year) +
                                                                         str(datetime.utcnow().month) +
                                                                         str(datetime.utcnow().day)
                                                                 ).encode('utf8')
                                                             ).hexdigest())
            db_session.commit()
    if not user_datastore.find_role('tempadmin'):
        temp_admin_role = user_datastore.find_or_create_role(name='tempadmin',
                                                             description='Initial admin with ability to only '
                                                                         'create new users.')
        db_session.commit()
    if not user_datastore.find_role('admin'):
        admin_role = user_datastore.find_or_create_role(name='admin',
                                                        description='User with read/write access to all API components'
                                                                    ', and the ability to create new users')
    if not user_datastore.find_role('superuser'):
        user_datastore.find_or_create_role(name='superuser',
                                           description='User with read/write access to all API components.')
        db_session.commit()
    if not user_datastore.find_role('analyst'):
        user_datastore.find_or_create_role(name='analyst',
                                           description='User with read access to all API components.')

        db_session.commit()
    if temp_admin_user and temp_admin_role:
        user_datastore.add_role_to_user(temp_admin_user, temp_admin_role)
        db_session.commit()

    if managerd_admin_user and admin_role:
        user_datastore.add_role_to_user(managerd_admin_user, admin_role)
        db_session.commit()
