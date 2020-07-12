from flask import flash, request, render_template, Blueprint
from dynamite_nsm.services.zeek import process as zeek_process
from dynamite_nsm.services.suricata import process as suricata_process
from dynamite_nsm import utilities
from flask_login import current_user

home_blueprint = Blueprint('home', __name__, template_folder='templates')


@home_blueprint.route('/')
def index():
    if request.referrer and 'create_admin' in request.referrer:
        flash('Login with your newly created profile account', category='success')
    elif request.referrer and 'create' in request.referrer:
        flash('New user created.', category='success')

    return render_template('home/home.html',
                           current_user=current_user,
                           analysis_engines_statuses={
                               'zeek': zeek_process.ProcessManager().status()['RUNNING'],
                               'suricata': suricata_process.ProcessManager().status()['RUNNING']
                           },
                           system_info={
                               'cpu_cores': utilities.get_cpu_core_count(),
                               'memory': utilities.get_memory_available_bytes()
                           }
                    )
