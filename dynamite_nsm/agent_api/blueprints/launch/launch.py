from flask import render_template, Blueprint
from flask_login import current_user

launch_blueprint = Blueprint('users', __name__, template_folder='templates')


@launch_blueprint.route('/')
def launch():
    return render_template('launch/launch.html', current_user=current_user)
