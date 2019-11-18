from get5 import app, db, flash_errors, config_setting
from models import GameServer
import util

from flask import Blueprint, request, render_template, flash, g, redirect

from wtforms import Form, validators, StringField, IntegerField, BooleanField

import os
import requests
import json
import ConfigParser

server_blueprint = Blueprint('server', __name__)


class ServerForm(Form):
    display_name = StringField('Display Name',
                               validators=[
                                   validators.Length(min=-1,
                                                     max=GameServer.display_name.type.length)])

    ip_string = StringField('Server IP',
                            validators=[
                                validators.required(),
                                validators.IPAddress()])

    port = IntegerField('Server port', default=27015,
                        validators=[validators.required()])

    gotv_port = IntegerField('GOTV port', default=27020,
                             validators=[validators.required()])

    rcon_password = StringField('RCON password',
                                validators=[
                                    validators.required(),
                                    validators.Length(min=-1,
                                                      max=GameServer.rcon_password.type.length)])

    public_server = BooleanField('Publicly usable server')

    dathost_id = StringField('Dathost ID')


@server_blueprint.route('/server/create', methods=['GET', 'POST'])
def server_create():
    if not g.user:
        return redirect('/login')

    form = ServerForm(request.form)
    if request.method == 'POST':
        num_servers = g.user.servers.count()
        max_servers = config_setting('USER_MAX_SERVERS')
        if max_servers >= 0 and num_servers >= max_servers and not g.user.admin:
            flash('You already have the maximum number of servers ({}) stored'.format(
                num_servers))

        elif form.validate():
            mock = config_setting('TESTING')

            data = form.data
            server = GameServer.create(g.user,
                                       data['display_name'],
                                       data['ip_string'],
                                       data['port'],
                                       data['gotv_port'],
                                       data['rcon_password'],
                                       data['dathost_id'],
                                       data['public_server'] and g.user.admin)

            if mock or util.check_server_connection(server):
                db.session.commit()
                app.logger.info(
                    'User {} created server {}'.format(g.user.id, server.id))
                return redirect('/myservers')
            else:
                db.session.remove()
                flash('Failed to connect to server')

        else:
            flash_errors(form)

    return render_template('server_create.html', user=g.user, form=form,
                           edit=False, is_admin=g.user.admin)


@server_blueprint.route('/server/<int:serverid>/edit', methods=['GET', 'POST'])
def server_edit(serverid):
    server = GameServer.query.get_or_404(serverid)
    is_owner = (g.user and (g.user.id == server.user_id)) or g.user.admin
    if not is_owner:
        return 'Not your server', 400

    form = ServerForm(request.form,
                      display_name=server.display_name,
                      ip_string=server.ip_string,
                      port=server.port,
                      gotv_port=server.gotv_port,
                      rcon_password=server.rcon_password,
                      public_server=server.public_server,
                      dathost_id=server.dathost_id)

    if request.method == 'POST':
        if form.validate():
            mock = app.config['TESTING']

            data = form.data
            server.display_name = data['display_name']
            server.ip_string = data['ip_string']
            server.port = data['port']
            server.gotv_port = data['gotv_port']
            server.rcon_password = data['rcon_password']
            server.dathost_id = ['dathost_id']
            server.public_server = (data['public_server'] and g.user.admin)

            if mock or util.check_server_connection(server):
                db.session.commit()
                return redirect('/myservers')
            else:
                db.session.remove()
                flash('Failed to connect to server')

        else:
            flash_errors(form)

    return render_template('server_create.html', user=g.user, form=form,
                           edit=True, is_admin=g.user.admin)


@server_blueprint.route('/server/<int:serverid>/start', methods=['GET'])
def server_start(serverid):
    server = GameServer.query.get_or_404(serverid)

    if server.in_use:
        return 'Server is in use', 400

    config = ConfigParser.ConfigParser()
    config.read("/etc/get5credentials.txt")

    user = config.get("dathost", "username")
    password = config.get("dathost", "password")

    response = requests.post(
        'https://dathost.net/api/0.1/game-servers/{}/start'.format(server.dathost_id), auth=(user, password))
    if response.status_code == 200:
        flash('Server started successfully', 'success')
    else:
        flash('Could not start server', 'error')

    return redirect('myservers')


@server_blueprint.route('/server/<int:serverid>/stop', methods=['GET'])
def server_stop(serverid):
    server = GameServer.query.get_or_404(serverid)
    is_owner = (g.user is not None) and (g.user.id == server.user_id)
    if not is_owner:
        return 'Not your server', 400

    if server.in_use:
        return 'Cannot delete when in use', 400

    return redirect('myservers')


@server_blueprint.route('/server/<int:serverid>/delete', methods=['GET'])
def server_delete(serverid):
    server = GameServer.query.get_or_404(serverid)
    is_owner = (g.user is not None) and (g.user.id == server.user_id)
    if not is_owner:
        return 'Not your server', 400

    if server.in_use:
        return 'Cannot delete when in use', 400

    matches = g.user.matches.filter_by(server_id=serverid)
    for m in matches:
        m.server_id = None

    GameServer.query.filter_by(id=serverid).delete()
    db.session.commit()
    return redirect('myservers')


@server_blueprint.route("/myservers")
def myservers():
    if not g.user:
        return redirect('/login')

    if g.user.admin:
        # all public servers
        servers = GameServer.query.filter_by(
            public_server=True).order_by(-GameServer.id).limit(50)

    ownservers = GameServer.query.filter_by(
        user_id=g.user.id).order_by(-GameServer.id).limit(50)

    return render_template('servers.html', user=g.user, servers=servers, ownservers=ownservers)
