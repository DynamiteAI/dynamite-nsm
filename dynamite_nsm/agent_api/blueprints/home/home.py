from flask import flash, render_template, Blueprint
from flask_login import current_user

home_blueprint = Blueprint('home', __name__, template_folder='templates')


@home_blueprint.route('/')
def index():
    flash('Welcome!')
    return render_template('home/home.html', current_user=current_user)
