import os
import traceback

from werkzeug import secure_filename
from flask_security import roles_accepted
from flask import request, redirect, flash, jsonify, render_template, Blueprint


from dynamite_nsm import const
from dynamite_nsm.agent_ui.plugin_framework import load_plugins, install_plugin, uninstall_plugin

plugins_blueprint = Blueprint('plugins', __name__, template_folder='templates')

ALLOWED_EXTENSIONS = ['zip']


@roles_accepted('admin')
@plugins_blueprint.route('/')
def render_plugins_ui_html():
    return render_template('admin/plugins.html', plugins=load_plugins(disable_load=True))


@roles_accepted('admin')
@plugins_blueprint.route('/error',  methods=['POST'])
def render_install_plugin_error():
    error = {
        'type': request.form['error_type'],
        'message': request.form['error_message'],
        'traceback': request.form['error_traceback']
    }
    return render_template('admin/install_plugin_error.html', plugins=load_plugins(disable_load=True), error=error)


@roles_accepted('admin')
@plugins_blueprint.route('/install')
def render_plugin_install_ui_html():
    return render_template('admin/install_plugin.html', plugins=load_plugins(disable_load=True))


@roles_accepted('admin')
@plugins_blueprint.route('/install_plugin_ajax', methods=['POST'])
def install_ui_plugin():
    def allowed_file(filename):
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(const.INSTALL_CACHE, filename))
            try:
                install_plugin(os.path.join(const.INSTALL_CACHE, filename))
                return jsonify(
                    {"message": "Success. Plugin installed successfully."}
                ), 200
            except Exception as e:
                return jsonify(
                    {"error_type": e.__class__.__name__,
                     "error_message": str(e),
                     "error_traceback": traceback.format_exc(limit=3)}
                ), 200


@roles_accepted('admin')
@plugins_blueprint.route('/uninstall_plugin_submit/<plugin_id>')
def uninstall_ui_plugin(plugin_id):
    uninstall_plugin(plugin_id)
    return redirect('/plugins')



