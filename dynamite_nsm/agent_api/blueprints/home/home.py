from flask import flash, request, render_template, Blueprint
from flask_login import current_user

home_blueprint = Blueprint('home', __name__, template_folder='templates')


@home_blueprint.route('/')
def index():
    if not request.referrer:
        return render_template('home/home.html', current_user=current_user)
    if 'create_admin' in request.referrer:
        flash('Login with your newly created admin account', category='success')
    elif 'create' in request.referrer:
        flash('New user created.', category='success')

    return render_template('home/home.html', current_user=current_user)
