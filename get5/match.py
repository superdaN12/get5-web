from flask import Blueprint, request, render_template, flash, g, redirect, jsonify, Markup, send_file, send_from_directory

import steamid
import get5
from get5 import app, db, BadRequestError, config_setting
from models import User, Team, Match, GameServer
import util

import zipfile
import io
import pathlib

import os, json, requests

from wtforms import (
    Form, widgets, validators,
    StringField, RadioField, 
    SelectField, ValidationError, SelectMultipleField)

match_blueprint = Blueprint('match', __name__)


class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()


def different_teams_validator(form, field):
    if form.team1_id.data == form.team2_id.data:
        raise ValidationError('Teams cannot be equal')

def different_maps_validator(form, field):
    if form.mappick_team1.data == form.mappick_team2.data:
        raise ValidationError('Maps cannot be equal')

def mappool_validator(form, field):
    if 'preset' in form.series_type.data and len(form.veto_mappool.data) != 1:
        raise ValidationError(
            'You must have exactly 1 map selected to do a bo1 with a preset map')

    max_maps = 1
    try:
        max_maps = int(form.series_type.data[2])
    except ValueError:
        max_maps = 1

    if len(form.veto_mappool.data) < max_maps and max_maps != 2:
        raise ValidationError(
            'You must have at least {} maps selected to do a Bo{}'.format(max_maps, max_maps))


class MatchForm(Form):
    server_id = SelectField('Server', coerce=int,
                            validators=[validators.required()])

    match_title = StringField('Match title text',
                              default='Map {MAPNUMBER} of {MAXMAPS}',
                              validators=[validators.Length(min=-1, max=Match.title.type.length)])

    series_type = RadioField('Series type',
                             validators=[validators.required()],
                             default='bo2',
                             choices=[
                                 ('bo1-preset', 'Bo1 with preset map - (Knife preset, ignore sidepick of teams)'),
                                 ('bo2', 'Bo2 with preset maps - (Sidepick A & B)'),
                                 ('bo3', 'Bo3 with preset maps - (Sidepick A & B + Knife)'),
                             ])

    sidepick_team1 = RadioField('Sidepick Team A for Map 2 (BO2/BO3)',
                                validators=[validators.required()],
                                default='team1_ct',
                                choices =[
                                    ('team1_ct', 'CT'),
                                    ('team1_t', 'T'),
                                ])

    sidepick_team2 = RadioField('Sidepick Team B for Map 1 (BO2/BO3)',
                                validators=[validators.required()],
                                default='team2_ct',
                                choices =[
                                    ('team2_ct', 'CT'),
                                    ('team2_t', 'T'),
                                ])

    team1_id = SelectField('Team A', coerce=int,
                           validators=[validators.required()])

    team1_string = StringField('Team A title text',
                               default='',
                               validators=[validators.Length(min=-1,
                                                             max=Match.team1_string.type.length)])

    mappick_team1 = SelectField('Mappick Team A')

    team2_id = SelectField('Team B', coerce=int,
                           validators=[validators.required(), different_teams_validator])

    team2_string = StringField('Team B title text',
                               default='',
                               validators=[validators.Length(min=-1,
                                                             max=Match.team2_string.type.length)])

    mappick_team2 = SelectField('Mappick Team B', default='')

    mappick_bo3 = SelectField('Mappick Last Map BO3', default='')

    mapchoices = config_setting('MAPLIST')
    default_mapchoices = config_setting('DEFAULT_MAPLIST')

    veto_mappool = MultiCheckboxField('Map pool',
                                      choices=map(lambda name: (
                                          name, util.format_mapname(
                                              name)), mapchoices),
                                      default=default_mapchoices,
                                      )

    def add_teams(self, user):
        if self.team1_id.choices is None:
            self.team1_id.choices = []

        if self.team2_id.choices is None:
            self.team2_id.choices = []

        team_ids = [team.id for team in user.teams]
        for team in Team.query.filter_by(public_team=True):
            if team.id not in team_ids:
                team_ids.append(team.id)

        team_tuples = []
    
        for teamid in team_ids:
            team_tuples.append((teamid, Team.query.get(teamid).name))

        team_tuples.sort(key=lambda tup: tup[1])
        
        self.team1_id.choices += team_tuples
        self.team2_id.choices += team_tuples

    def add_servers(self, user):
        if self.server_id.choices is None:
            self.server_id.choices = []

        server_ids = []
        for s in user.servers:
            if not s.in_use:
                server_ids.append(s.id)

        for s in GameServer.query.filter_by(public_server=True):
            if not s.in_use and s.id not in server_ids:
                server_ids.append(s.id)

        server_tuples = []
        for server_id in server_ids:
            server_tuples.append(
                (server_id, GameServer.query.get(server_id).get_display()))

        self.server_id.choices += server_tuples

    def add_maps(self, user):
        if self.mappick_team1.choices is None:
            self.mappick_team1.choices = []
        
        mapchoices = config_setting('MAPLIST')

        if self.mappick_team2.choices is None:
            self.mappick_team2.choices = []

        self.mappick_team1.choices = map(lambda name: (
                                          name, util.format_mapname(
                                              name)), mapchoices)

        self.mappick_team2.choices = map(lambda name: (
                                          name, util.format_mapname(
                                              name)), mapchoices)

        self.mappick_bo3.choices = map(lambda name: (
                                          name, util.format_mapname(
                                              name)), mapchoices)


@match_blueprint.route('/match/create', methods=['GET', 'POST'])
def match_create():
    if not g.user:
        return redirect('/login')

    form = MatchForm(request.form)
    form.add_teams(g.user)
    form.add_servers(g.user)
    form.add_maps(g.user)

    if request.method == 'POST':
        num_matches = g.user.matches.count()
        max_matches = config_setting('USER_MAX_MATCHES')

        if max_matches >= 0 and num_matches >= max_matches and not g.user.admin:
            flash('You already have the maximum number of matches ({}) created'.format(
                num_matches))

        if form.validate():
            mock = config_setting('TESTING')

            server = GameServer.query.get_or_404(form.data['server_id'])

            match_on_server = g.user.matches.filter_by(
                server_id=server.id, end_time=None, cancelled=False).first()

            server_avaliable = False
            json_reply = None

            if g.user.id != server.user_id and not server.public_server:
                server_avaliable = False
                message = 'This is not your server!'
            elif match_on_server is not None:
                server_avaliable = False
                message = 'Match {} is already using this server'.format(
                    match_on_server.id)
            elif mock:
                server_avaliable = True
                message = 'Success'
            else:
                json_reply, message = util.check_server_avaliability(
                    server)
                server_avaliable = (json_reply is not None)

            if server_avaliable:
                skip_veto = 'preset' in form.data['series_type']
                try:
                    max_maps = int(form.data['series_type'][2])
                except ValueError:
                    max_maps = 1

                match = Match.create(
                    g.user, form.data['team1_id'], form.data['team2_id'],
                    form.data['team1_string'], form.data['team2_string'],
                    max_maps, skip_veto, form.data['match_title'],
                    form.data['veto_mappool'], form.data['server_id'],
                    form.data['mappick_team1'], form.data['mappick_team2'], 
                    form.data['sidepick_team1'], form.data['sidepick_team2'],
                    form.data['mappick_bo3'])

                # Save plugin version data if we have it
                if json_reply and 'plugin_version' in json_reply:
                    match.plugin_version = json_reply['plugin_version']
                else:
                    match.plugin_version = 'unknown'

                server.in_use = True

                db.session.commit()
                app.logger.info('User {} created match {}, assigned to server {}'
                                .format(g.user.id, match.id, server.id))

                if mock or match.send_to_server():
                    return redirect('/mymatches')
                else:
                    flash('Failed to load match configs on server')
            else:
                flash(message)

        else:
            get5.flash_errors(form)

    return render_template(
        'match_create.html', form=form, user=g.user, teams=g.user.teams,
                           match_text_option=config_setting('CREATE_MATCH_TITLE_TEXT'))


@match_blueprint.route('/match/<int:matchid>')
def match(matchid):
    match = Match.query.get_or_404(matchid)
    team1 = Team.query.get_or_404(match.team1_id)
    team2 = Team.query.get_or_404(match.team2_id)
    map_stat_list = match.map_stats.all()

    is_owner = False
    has_admin_access = False

    if g.user:
        is_owner = (g.user.id == match.user_id)
        has_admin_access = is_owner or (config_setting(
            'ADMINS_ACCESS_ALL_MATCHES') and g.user.admin)

    return render_template(
        'match.html', user=g.user, admin_access=has_admin_access,
                           match=match, team1=team1, team2=team2,
                           map_stat_list=map_stat_list)


@match_blueprint.route('/match/<int:matchid>/config')
def match_config(matchid):
    match = Match.query.get_or_404(matchid)
    dict = match.build_match_dict()
    json_text = jsonify(dict)
    return json_text


def admintools_check(user, match):
    if user is None:
        raise BadRequestError('You do not have access to this page')

    grant_admin_access = user.admin and get5.config_setting(
        'ADMINS_ACCESS_ALL_MATCHES')
    if user.id != match.user_id and not grant_admin_access:
        raise BadRequestError('You do not have access to this page')

    if match.finished():
        raise BadRequestError('Match already finished')

    if match.cancelled:
        raise BadRequestError('Match is cancelled')

def admintools_checkdelete(user, match):
    if user is None:
        raise BadRequestError('You do not have access to this page')

    grant_admin_access = user.admin and get5.config_setting(
        'ADMINS_ACCESS_ALL_MATCHES')
    if user.id != match.user_id and not grant_admin_access:
        raise BadRequestError('You do not have access to this page')

    if match.finished():
        raise BadRequestError('Match already finished')

    if match.start_time is not None:
        raise BadRequestError('Match already started')


@match_blueprint.route('/match/<int:matchid>/cancel')
def match_cancel(matchid):
    match = Match.query.get_or_404(matchid)
    admintools_check(g.user, match)

    match.cancelled = True
    server = GameServer.query.get(match.server_id)
    if server:
        server.in_use = False

    db.session.commit()

    try:
        server.send_rcon_command('get5_endmatch', raise_errors=True)
    except util.RconError as e:
        flash('Failed to cancel match: ' + str(e))

    return redirect('/mymatches')

@match_blueprint.route('/match/<int:matchid>/delete')
def match_delete(matchid):
    match = Match.query.get_or_404(matchid)
    admintools_checkdelete(g.user, match)

    if match.cancelled: 
        try:
            db.session.delete(match)
            db.session.commit()
        except Exception as e:
            flash('Failed to delete match: ' + str(e))

    return redirect('/mymatches')
    
@match_blueprint.route('/match/<int:matchid>/load_file/')
def load_file(matchid):
    match = Match.query.get_or_404(matchid)
    demoname = '{}map1{}'.format('49', match.mappick_team1)

    # zf = zipfile.ZipFile(demoname + '.zip','w')
    # files = result['files']
    # for individualFile in files:
    #     data = zipfile.ZipInfo(individualFile[demoname + '.dem'])
    #     data.date_time = time.localtime(time.time())[:6]
    #     data.compress_type = zipfile.ZIP_DEFLATED
    #     zf.writestr(data,individualFile[demoname + '.dem'])
    # return send_file(BytesIO(zf), attachment_filename=demoname + '.zip', as_attachment=True)

    return send_from_directory(
        '/home/ftpdemos/', 
        demoname + '.zip',
        as_attachment=True,
        attachment_filename= demoname + '.zip'
    )

@match_blueprint.route('/match/<int:matchid>/load_demo_map1/')
def load_demo_map1(matchid):
    match = Match.query.get_or_404(matchid)
    demoname = '{}map1{}'.format(match.id, match.mappick_team1)

    return send_from_directory(
        '/home/ftpdemos/', 
        demoname + '.zip',
        as_attachment=True,
        attachment_filename= demoname + '.zip'
    )

@match_blueprint.route('/match/<int:matchid>/load_demo_map2/')
def load_demo_map2(matchid):
    match = Match.query.get_or_404(matchid)
    demoname = '{}map2{}'.format(match.id, match.mappick_team2)

    return send_from_directory(
        '/home/ftpdemos/', 
        demoname + '.zip',
        as_attachment=True,
        attachment_filename= demoname + '.zip'
    )

@match_blueprint.route('/match/<int:matchid>/load_demo_map3/')
def load_demo_map3(matchid):
    match = Match.query.get_or_404(matchid)
    demoname = '{}map3{}'.format(match.id, match.mappick_bo3)

    return send_from_directory(
        '/home/ftpdemos/', 
        demoname + '.zip',
        as_attachment=True,
        attachment_filename= demoname + '.zip'
    )

@match_blueprint.route('/match/<int:matchid>/rcon')
def match_rcon(matchid):
    match = Match.query.get_or_404(matchid)
    admintools_check(g.user, match)

    command = request.values.get('command')
    server = GameServer.query.get_or_404(match.server_id)

    if command:
        try:
            rcon_response = server.send_rcon_command(
                command, raise_errors=True)
            if rcon_response:
                rcon_response = Markup(rcon_response.replace('\n', '<br>'))
            else:
                rcon_response = 'No output'
            flash(rcon_response)
        except util.RconError as e:
            print(e)
            flash('Failed to send command: ' + str(e))

    return redirect('/match/{}'.format(matchid))


@match_blueprint.route('/match/<int:matchid>/pause')
def match_pause(matchid):
    match = Match.query.get_or_404(matchid)
    admintools_check(g.user, match)
    server = GameServer.query.get_or_404(match.server_id)

    try:
        server.send_rcon_command('sm_pause', raise_errors=True)
        flash('Paused match')
    except util.RconError as e:
        flash('Failed to send pause command: ' + str(e))

    return redirect('/match/{}'.format(matchid))


@match_blueprint.route('/match/<int:matchid>/unpause')
def match_unpause(matchid):
    match = Match.query.get_or_404(matchid)
    admintools_check(g.user, match)
    server = GameServer.query.get_or_404(match.server_id)

    try:
        server.send_rcon_command('sm_unpause', raise_errors=True)
        flash('Unpaused match')
    except util.RconError as e:
        flash('Failed to send unpause command: ' + str(e))

    return redirect('/match/{}'.format(matchid))


@match_blueprint.route('/match/<int:matchid>/adduser')
def match_adduser(matchid):
    match = Match.query.get_or_404(matchid)
    admintools_check(g.user, match)
    server = GameServer.query.get_or_404(match.server_id)
    team = request.values.get('team')
    if not team:
        raise BadRequestError('No team specified')

    auth = request.values.get('auth')
    suc, new_auth = steamid.auth_to_steam64(auth)
    if suc:
        try:
            command = 'get5_addplayer {} {}'.format(new_auth, team)
            response = server.send_rcon_command(command, raise_errors=True)
            flash(response)
        except util.RconError as e:
            flash('Failed to send command: ' + str(e))

    else:
        flash('Invalid steamid: {}'.format(auth))

    return redirect('/match/{}'.format(matchid))


# @match_blueprint.route('/match/<int:matchid>/sendconfig')
# def match_sendconfig(matchid):
#     match = Match.query.get_or_404(matchid)
#     admintools_check(g.user, match)
#     server = GameServer.query.get_or_404(match.server_id)

#     try:
#         server.send_rcon_command('mp_unpause_match', raise_errors=True)
#         flash('Unpaused match')
#     except util.RconError as e:
#         flash('Failed to send unpause command: ' + str(e))

#     return redirect('/match/{}'.format(matchid))


@match_blueprint.route('/match/<int:matchid>/backup', methods=['GET'])
def match_backup(matchid):
    match = Match.query.get_or_404(matchid)
    admintools_check(g.user, match)
    server = GameServer.query.get_or_404(match.server_id)
    file = request.values.get('file')

    if not file:
        # List backup files
        backup_response = server.send_rcon_command(
            'get5_listbackups ' + str(matchid))
        if backup_response:
            backup_files = sorted(backup_response.split('\n'))
        else:
            backup_files = []

        return render_template('match_backup.html', user=g.user,
                               match=match, backup_files=backup_files)

    else:
        # Restore the backup file
        command = 'get5_loadbackup {}'.format(file)
        response = server.send_rcon_command(command)
        if response:
            flash('Restored backup file {}'.format(file))
        else:
            flash('Failed to restore backup file {}'.format(file))
            return redirect('match/{}/backup'.format(matchid))

        return redirect('match/{}'.format(matchid))


@match_blueprint.route("/matches")
def matches():
    page = util.as_int(request.values.get('page'), on_fail=1)
    matches = Match.query.order_by(-Match.id).filter_by(
        cancelled=False).paginate(page, 20)
    return render_template('matches.html', user=g.user, matches=matches,
                           my_matches=False, all_matches=True, page=page)

@match_blueprint.route("/matchesliga1")
def matchesliga2():
    page = util.as_int(request.values.get('page'), on_fail=1)
    matches = Match.query.order_by(-Match.id).filter_by(
        cancelled=False).join(Team, Match.team1_id==Team.id).filter_by(
            bracket='Liga 1').paginate(page, 20)

    return render_template('matchesliga1.html', user=g.user, matches=matches,
                           my_matches=False, all_matches=True, page=page)

@match_blueprint.route("/matchesliga2")
def matchesliga1():
    page = util.as_int(request.values.get('page'), on_fail=1)
    matches = Match.query.order_by(-Match.id).filter_by(
        cancelled=False).join(Team, Match.team1_id==Team.id).filter_by(
            bracket='Liga 2').paginate(page, 20)
    return render_template('matchesliga2.html', user=g.user, matches=matches,
                           my_matches=False, all_matches=True, page=page)

@match_blueprint.route("/matchesliga3")
def matchesliga3():
    page = util.as_int(request.values.get('page'), on_fail=1)
    matches = Match.query.order_by(-Match.id).filter_by(
        cancelled=False).join(Team, Match.team1_id==Team.id).filter_by(
            bracket='Liga 3').paginate(page, 20)
    return render_template('matchesliga3.html', user=g.user, matches=matches,
                           my_matches=False, all_matches=True, page=page)

@match_blueprint.route("/matches/<int:userid>")
def matches_user(userid):
    user = User.query.get_or_404(userid)
    page = util.as_int(request.values.get('page'), on_fail=1)
    if user.admin:
        matches= Match.query.order_by(-Match.id).paginate(page, 20)
        is_owner = user.admin
    else:
        matches = user.matches.order_by(-Match.id).paginate(page, 20)
        is_owner = (g.user is not None) and (userid == g.user.id)
   
    return render_template('matches.html', user=g.user, matches=matches,
                           my_matches=is_owner, all_matches=False, match_owner=user, page=page)


@match_blueprint.route("/mymatches")
def mymatches():
    if not g.user:
        return redirect('/login')

    return redirect('/matches/' + str(g.user.id))
