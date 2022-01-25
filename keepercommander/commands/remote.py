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
from keepercommander import api
from keepercommander.subfolder import try_resolve_path

import jwt
import requests
import urllib


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


def get_url_token(record, login, public_key, scope):
    token_vars = {
        'login': login,
        'public-key': public_key,
        'scope': ' '.join(scope)
    }
    for f in record.custom_fields:
        for k, v in JWK_FIELDS.items():
            if f['name'] == v:
                token_vars[k] = f['value']
    for k, v in JWK_FIELDS.items():
        if v.startswith('url:') and k not in token_vars:
            token_vars[k] = record.login_url
            break

    token_vars['exp'] = int(time()) + JWT_EXP_DELTA

    payload = {k: token_vars[k] for k in ['exp', 'aud', 'iss', 'kid', 'login', 'public-key', 'scope']}
    headers = {k: token_vars[k] for k in ['alg', 'kid']}
    jwt_token = jwt.encode(payload, token_vars['key']['privateKey'], headers=headers)
    return token_vars['api'], jwt_token


def decode_token(jwt_token):
    payload = jwt.decode(jwt_token, options={'verify_signature': False})
    headers = jwt.get_unverified_header(jwt_token)
    return payload, headers


class RemoteCommand(Command):
    def get_parser(self):
        return remote_parser

    def execute(self, params, **kwargs):
        v3_enabled = params.settings.get('record_types_enabled') if params.settings and isinstance(params.settings.get('record_types_enabled'), bool) else False
        if not v3_enabled:
            logging.warning(f"Record types are needed for remote commands")
            return

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

        root_key_path = kwargs.get('root_key')
        if root_key_path:
            root_key = get_record(params, root_key_path)
            if root_key:
                logging.info(f'Found root key {root_key.title}')
            else:
                logging.warning(f"Can't find root key {root_key_path}")
        else:
            root_key = None

        remote_obj = remote_command[0]
        remote_action = remote_command[1] if len(remote_command) > 1 else None

        if remote_obj == 'user':
            if not root_key:
                logging.warning('--root-key option required')
                return

            if remote_action == 'add':
                user_public_pem = params.rsa_key.public_key().exportKey(format='PEM')
                user_public_key = ''.join(user_public_pem.decode().splitlines()[1:-1])
                api_url, jwt_token = get_url_token(
                    root_key, login=params.user, public_key=user_public_key, scope=['user']
                )
                url_parts = urllib.parse.urlsplit(api_url)._asdict()
                if url_parts['path'] == '/':
                    url_parts['path'] = 'user'
                url = urllib.parse.urlunsplit(url_parts.values())

                payload, headers = decode_token(jwt_token)
                logging.debug(f'JWT token payload: {pprint.pformat(payload)}')
                logging.debug(f'JWT token headers: {pprint.pformat(headers)}')
                r = requests.get(url, headers={'Authorization': f'Bearer {jwt_token}'})

                pprint.pprint(json.loads(r.text))
                if r.status_code == 200:
                    logging.info('User added')
                else:
                    logging.warning('Failed to add user')
