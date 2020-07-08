from flask import flash, request, render_template, Blueprint
from flask_login import current_user

api_blueprint = Blueprint('api', __name__, template_folder='templates')


@api_blueprint.route('/')
def api():
    return render_template('api/api_dashboard.html', current_user=current_user)
