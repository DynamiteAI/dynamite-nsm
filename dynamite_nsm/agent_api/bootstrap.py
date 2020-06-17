from dynamite_nsm.agent_api import models
from dynamite_nsm.agent_api.database import db_session, init_db
from flask_security import Security, SQLAlchemySessionUserDatastore


def create_default_user_and_roles(flask_app):
    user_datastore = SQLAlchemySessionUserDatastore(db_session, models.User, models.Role)
    Security(flask_app, user_datastore)
    init_db()
    admin_user, admin_role = None, None
    if not user_datastore.find_user(email='admin@dynamite.local'):
        admin_user = user_datastore.create_user(email='admin@dynamite.local', username='admin', password='changeme')
        db_session.commit()
    if not user_datastore.find_role('admin'):
        admin_role = user_datastore.find_or_create_role(name='admin',
                                                        description='User with read/write access to all API components'
                                                                    ', and the ability to create new users')
        db_session.commit()
    if not user_datastore.find_role('superuser'):
        user_datastore.find_or_create_role(name='superuser',
                                           description='User with read/write access to all API components.')
        db_session.commit()
    if not user_datastore.find_role('analyst'):
        user_datastore.find_or_create_role(name='analyst',
                                           description='User with read access to all API components.')

        db_session.commit()
    if admin_user and admin_role:
        user_datastore.add_role_to_user(admin_user, admin_role)
        db_session.commit()
