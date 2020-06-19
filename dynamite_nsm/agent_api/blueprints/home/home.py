from flask import render_template, Blueprint
from flask_login import current_user

home_blueprint = Blueprint('home', __name__, template_folder='templates')


@home_blueprint.route('/')
def index():
    return render_template('launch/launch.html', current_user=current_user)
