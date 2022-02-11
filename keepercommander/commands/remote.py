#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
import argparse
import json
import logging
import pprint
from time import time

from .base import Command, raise_parse_exception, suppress_exit
from .recordv3 import RecordAddCommand
from keepercommander import api
from keepercommander.subfolder import try_resolve_path

import jwt
import requests
import websocket


AUTH_URL = 'https://xmr2imqr1d.execute-api.us-east-1.amazonaws.com/'
JWK_FIELDS = {
    'alg': 'text:alg',
    'api': 'url:api',
    'aud': 'text:aud',
    'iss': 'url:iss',
    'kid': 'text:kid',
    'key': 'keyPair:key'
}
JWT_EXP_DELTA = 7200  # 2 hours


def register_commands(commands):
    commands['remote'] = RemoteCommand()


def register_command_info(aliases, command_info):
    command_info[remote_parser.prog] = remote_parser.description


remote_subcommands = [
    'user add', 'minion add'
]
remote_parser = argparse.ArgumentParser(prog='remote', description='Run commands on remote minions')
remote_parser.add_argument('--force', dest='force', action='store_true', help='Force record creation when exists')
remote_parser.add_argument(
    '-f', '--folder', dest='remote_folder', action='store', help='Remote control record folder'
)
remote_parser.add_argument(
    '-k', '--root-key', dest='root_key', action='store', help='Root key record for signing stored as JWK record type'
)
remote_parser.add_argument(
    '-r', '--role', dest='role', action='append', help='User role that can be used multiple times'
)
remote_parser.add_argument(
    '-u', '--user-id', dest='user_id', action='store', help='User id'
)
remote_parser.add_argument(
    '-m', '--minion-id', dest='minion_id', action='store', help='Minion id'
)
remote_parser.add_argument(
    '-e', '--expire-token-delta', type=int, dest='exp_delta', action='store', default=JWT_EXP_DELTA,
    help='Expiration delta of minion authentication token in seconds'
)
remote_parser.add_argument(
    'command', type=str, action='store', nargs="*", help='One of: "{}"'.format('", "'.join(remote_subcommands))
)
remote_parser.error = raise_parse_exception
remote_parser.exit = suppress_exit


def find_folder_record(params, base_folder, record_name, v3_enabled):
    folder_uid = base_folder.uid
    if folder_uid in params.subfolder_record_cache:
        for uid in params.subfolder_record_cache[folder_uid]:
            rv = params.record_cache[uid].get('version') if params.record_cache and uid in params.record_cache else None
            if rv == 4 or rv == 5:
                continue  # skip fileRef and application records - they use file-report command
            if not v3_enabled and rv in (3, 4):
                continue  # skip record types when not enabled
            r = api.get_record(params, uid)
            if r.title.lower() == record_name.lower():
                return r

    return None


def get_folder(params, folder_path):
    folder = params.folder_cache.get(params.current_folder, params.root_folder)
    rs = try_resolve_path(params, folder_path)
    if rs is not None:
        folder, name = rs
        if len(name) > 0:
            return None
    return folder


def get_record(params, record_path):
    folder = None
    name = None
    if record_path:
        rs = try_resolve_path(params, record_path)
        if rs is not None:
            folder, name = rs

    if folder is None or name is None:
        return None

    if name in params.record_cache:
        return api.get_record(params, name)
    else:
        return find_folder_record(params, folder, name, v3_enabled=True)


def get_auth_token(record, login, scopes, public_key=None, exp_delta=JWT_EXP_DELTA):
    token_vars = {
        'login': login,
        'scopes': ','.join(scopes)
    }
    for f in record.custom_fields:
        for k, v in JWK_FIELDS.items():
            if f['name'] == v:
                token_vars[k] = f['value']
    for k, v in JWK_FIELDS.items():
        if v.startswith('url:') and k not in token_vars:
            token_vars[k] = record.login_url
            break

    token_vars['exp'] = int(time()) + exp_delta

    payload = {k: token_vars[k] for k in ['exp', 'aud', 'iss', 'kid', 'login', 'scopes']}
    if public_key:
        payload['public-key'] = public_key

    headers = {k: token_vars[k] for k in ['alg', 'kid']}
    jwt_token = jwt.encode(payload, token_vars['key']['privateKey'], headers=headers)
    return token_vars['api'], jwt_token


def decode_token(jwt_token):
    payload = jwt.decode(jwt_token, options={'verify_signature': False})
    headers = jwt.get_unverified_header(jwt_token)
    return payload, headers


def get_ws_response(ws, print_msg=True):
    response = ''
    while response is not None:
        try:
            resp_json = ws.recv()
        except ConnectionAbortedError:
            logging.warning('Websocket connection timed out')
            response = None
        except websocket.WebSocketTimeoutException:
            # This is actually not an error; there are just no more responses.
            response = None

        else:
            try:
                resp_dict = json.loads(resp_json)
            except json.JSONDecodeError:
                logging.warning(f'Invalid websocket response: {resp_dict}')
                response = resp_json

            else:
                if isinstance(resp_dict, dict) and len(resp_dict) > 0:
                    response = []
                    members = resp_dict.pop('members', False)
                    message = resp_dict.pop('message', False)
                    command = resp_dict.pop('command', False)
                    if members:
                        member_list = '\n    '.join([''] + members)
                        response.append(f'members: {member_list}')
                    if command:
                        command_str = ' '.join(command)
                        response.append(f'command: {command_str}')
                    if message:
                        msg_from = resp_dict.pop('from', 'anonymous')
                        response.append(f'{msg_from}: {message}')
                    if len(resp_dict) > 0:
                        response.append(json.dumps(resp_dict))

                    if print_msg:
                        print('\n'.join(response))
                else:
                    logging.warning(f'Invalid websocket response: {resp_dict}')
                    response = resp_dict


class RemoteCommand(Command):
    def get_parser(self):
        return remote_parser

    def execute(self, params, **kwargs):
        v3_enabled = params.settings.get('record_types_enabled') if params.settings and isinstance(params.settings.get('record_types_enabled'), bool) else False
        if not v3_enabled:
            logging.warning(f"Record types are needed for remote commands")
            return

        force = kwargs.get('force', False)
        remote_command = kwargs.get('command')
        if len(remote_command) == 0:
            logging.warning('Please specify a subcommand to run')
            return

        remote_folder_path = kwargs.get('remote_folder')
        if remote_folder_path:
            remote_folder = get_folder(params, remote_folder_path)
            if remote_folder:
                logging.info(f'Found folder {remote_folder.name}')
            else:
                logging.warning(f"Can't find specified folder {remote_folder_path}")
        else:
            remote_folder = None

        root_key_path = kwargs.get('root_key')
        if root_key_path:
            root_key = get_record(params, root_key_path)
            if root_key:
                logging.info(f'Found root key {root_key.title}')
            else:
                logging.warning(f"Can't find root key {root_key_path}")
        else:
            root_key = None

        login = None
        remote_obj = remote_command[0]
        remote_action = remote_command[1] if len(remote_command) > 1 else None

        if remote_obj == 'minion' and remote_action == 'add':
            minion_id = kwargs.get('minion_id')
            if not minion_id:
                logging.warning('The --minion-id (-m) option is required')
                return
            if not remote_folder:
                logging.warning('The --folder (-f) option is required')
                return
            if not root_key:
                logging.warning('--root-key option required')
                return

            role = 'minion'
            jwt_exp_delta = kwargs.get('exp_delta', JWT_EXP_DELTA)
            api_url, jwt_token = get_auth_token(root_key, login=minion_id, scopes=[role], exp_delta=jwt_exp_delta)
            payload, headers = decode_token(jwt_token)
            logging.debug(f'JWT token payload: {pprint.pformat(payload)}')
            logging.debug(f'JWT token headers: {pprint.pformat(headers)}')

            command = RecordAddCommand()
            data = json.dumps({'type': 'remote-minion', 'title': minion_id, 'fields': [
                {'type': 'login', 'value': [minion_id]},
                {'type': 'url', 'value': [api_url]},
                {'type': 'secret', 'value': [jwt_token]}
            ]})
            command.execute(params, folder=remote_folder.uid, data=data, force=force)
            logging.info('Record for minion has been added')

        if remote_obj == 'user':
            role = 'user'
            if not login:
                login = kwargs.get('user_id') or params.user
            minion = kwargs.get('minion_id')
            if remote_action in ('cmd', 'disconnect', 'exit', 'list', 'ping', 'receive'):
                ws_connections = getattr(params, 'ws_connections', {})
                ws = ws_connections.get(login)
                if ws:
                    if remote_action == 'disconnect':
                        ws_connections.pop(login).close(timeout=3)
                        logging.info(f'{login} disconnected')

                    elif remote_action == 'receive':
                        get_ws_response(ws)

                    elif remote_action == 'list':
                        action_dict = {'action': 'list'}
                        if len(remote_command) > 2:
                            action_dict['role'] = remote_command[2]
                        ws.send(json.dumps(action_dict))
                        get_ws_response(ws)

                    elif remote_action == 'connectSocket':
                        if minion:
                            ws.send(json.dumps({'action': 'connectSocket', 'to': minion}))
                            logging.info(f'Socket connection to {minion} requested')
                        else:
                            logging.warning(f'Minion (--minion-id) not specified')

                    elif remote_action in ('cmd', 'exit', 'ping'):
                        cmd = remote_command[2:] if remote_action == 'cmd' else remote_command[1:]
                        if minion:
                            ws.send(json.dumps(
                                {'action': 'send', 'type': 'command', 'to': minion, 'message': cmd}
                            ))
                            get_ws_response(ws)
                            if cmd[0] == 'exit':
                                get_ws_response(ws)
                        else:
                            logging.warning(f'Minion (--minion-id) not specified')
                else:
                    logging.warning(f"Can't find connection for {login}")

            elif remote_action in ('check', 'connect'):
                if not root_key:
                    logging.warning('--root-key option required')
                    return

                user_public_pem = params.rsa_key.public_key().exportKey(format='PEM')
                user_public_key = ''.join(user_public_pem.decode().splitlines()[1:-1])
                api_url, jwt_token = get_auth_token(
                    root_key, login=login, scopes=[role], public_key=user_public_key
                )
                payload, headers = decode_token(jwt_token)
                logging.debug(f'JWT token payload: {pprint.pformat(payload)}')
                logging.debug(f'JWT token headers: {pprint.pformat(headers)}')

                if remote_action == 'check':
                    auth_url = f'{AUTH_URL}{role}'
                    r = requests.get(auth_url, headers={'Authorization': jwt_token})
                    pprint.pprint(json.loads(r.text))
                    if r.status_code == 200:
                        logging.info('User check successful')
                    else:
                        logging.warning('User check failed')
                else:
                    ws_connections = getattr(params, 'ws_connections', {})
                    ws = ws_connections.get(login)
                    if ws is None:
                        headers = {'Authorization': jwt_token, 'AuthRole': role, 'AuthUser': login}
                        ws = websocket.WebSocket()
                        ws.connect(api_url, timeout=3, header=headers)
                        ws_connections[login] = ws
                        params.ws_connections = ws_connections
                        logging.info(f'{login} connected')
                        if minion:
                            ws.send(json.dumps(
                                {'action': 'send', 'type': 'command', 'to': minion, 'message': ['ping']}
                            ))
                            get_ws_response(ws)
                    else:
                        logging.warning(f'User {login} is already connected')
