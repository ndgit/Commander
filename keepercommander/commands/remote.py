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
import os
from time import time

from .base import Command, raise_parse_exception, suppress_exit, user_choice
from keepercommander import api
from keepercommander.subfolder import BaseFolderNode, try_resolve_path
from keepercommander.params import LAST_SHARED_FOLDER_UID, LAST_FOLDER_UID

import jwt


PRIVATE_KEYS_FOLDER = 'private-keys'
ROOT_JWK_RECORD = 'root-jwk'
JWK_FIELDS = {
    'alg': 'text:alg',
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
    'admin request', 'admin accept'
]
remote_parser = argparse.ArgumentParser(prog='remote', description='Run commands on remote minions')
remote_parser.add_argument(
    '-f', '--folder', dest='remote_folder', action='store', help='Remote control record folder'
)
remote_parser.add_argument(
    '-r', '--role', dest='role', action='append', help='User role that can be used multiple times'
)
remote_parser.add_argument(
    'command', type=str, action='store', nargs="*", help='One of: "{}"'.format('", "'.join(remote_subcommands))
)
remote_parser.error = raise_parse_exception
remote_parser.exit = suppress_exit


def find_subfolder(params, base_folder, subfolder_name):
    subfolder_match = (
        params.folder_cache[x] for x in base_folder.subfolders if params.folder_cache[x].name == subfolder_name
    )
    return next(subfolder_match, None)


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


def create_folder(params, base_folder, request, folder_name):
    folder_uid = api.generate_record_uid()
    request['folder_uid'] = folder_uid

    folder_key = os.urandom(32)
    encryption_key = params.data_key
    if request['folder_type'] == 'shared_folder_folder':
        sf_uid = base_folder.shared_folder_uid if base_folder.type == BaseFolderNode.SharedFolderFolderType else base_folder.uid
        sf = params.shared_folder_cache[sf_uid]
        encryption_key = sf['shared_folder_key_unencrypted']
        request['shared_folder_uid'] = sf_uid

    request['key'] = api.encrypt_aes(folder_key, encryption_key)
    if base_folder.type not in (BaseFolderNode.RootFolderType, BaseFolderNode.SharedFolderType):
        request['parent_uid'] = base_folder.uid

    name = folder_name.strip()

    is_slash = False
    for x in range(0, len(name) - 2):
        if name[x] == '/':
            is_slash = not is_slash
        else:
            if is_slash:
                raise CommandError('mkdir', 'Character "/" is reserved. Use "//" inside folder name')

    name = name.replace('//', '/')

    if request['folder_type'] == 'shared_folder':
        request['name'] = api.encrypt_aes(name.encode('utf-8'), folder_key)

    data = {'name': name}
    request['data'] = api.encrypt_aes(json.dumps(data).encode('utf-8'), folder_key)

    api.communicate(params, request)
    params.sync_data = True
    params.environment_variables[LAST_FOLDER_UID] = folder_uid
    if request['folder_type'] == 'shared_folder':
        params.environment_variables[LAST_SHARED_FOLDER_UID] = folder_uid


def request_token(params, private_key_folder, login, public_key, scope):
    root_record = find_folder_record(params, private_key_folder, ROOT_JWK_RECORD, v3_enabled=True)
    if not root_record:
        logging.warning("Can't find root-key-pair for user request")
        return None
    root_dict = {}
    for f in root_record.custom_fields:
        for k, v in JWK_FIELDS:
            if f['name'] == v:
                root_dict[k] = f['value']

    root_private_key = root_dict['key']['privateKey']
    payload = {'kid': root_dict['kid'], 'login': login, 'public-key': public_key, 'scope': ' '.join(scope)}
    headers = {k: root_dict[k] for k in ['alg', 'aud', 'iss', 'kid']}
    headers['exp'] = int(time()) + JWT_EXP_DELTA
    jwt_token = jwt.encode(payload, root_private_key, headers=headers)
    return jwt_token


class RemoteCommand(Command):
    def get_parser(self):
        return remote_parser

    def execute(self, params, **kwargs):
        remote_command = kwargs.get('command')
        remote_folder_name = kwargs.get('remote_folder')

        if len(remote_command) == 0:
            logging.warning('Please specify a subcommand to run')
            return

        if not remote_folder_name:
            logging.warning('Please specify a folder name with the -f option')
            return

        base_folder = params.folder_cache.get(params.current_folder, params.root_folder)
        rs = try_resolve_path(params, remote_folder_name)
        if rs is not None:
            base_folder, name = rs
            if len(name) > 0:
                logging.warning(f"Can't find specified folder {remote_folder_name}")
                return
            else:
                logging.info(f'Found folder {base_folder.name}')

        remote_obj = remote_command[0]
        remote_action = remote_command[1] if len(remote_command) > 1 else None

        v3_enabled = params.settings.get('record_types_enabled') if params.settings and isinstance(params.settings.get('record_types_enabled'), bool) else False
        if not v3_enabled:
            logging.warning(f"Record types are needed for remote commands")
            return

        if remote_obj == 'user':
            if remote_action == 'add':
                private_key_folder = find_subfolder(params, base_folder, PRIVATE_KEYS_FOLDER)
                if private_key_folder:
                    logging.info(f'Found folder {PRIVATE_KEYS_FOLDER}')
                else:
                    prompt_msg = (
                        f'The folder "{PRIVATE_KEYS_FOLDER}" is not found. '
                        f'Add "{PRIVATE_KEYS_FOLDER}" to "{base_folder.name}"?'
                    )
                    choice = user_choice(f'\n{prompt_msg}', 'yn', default='n')
                    if choice.lower() == 'n':
                        logging.warning(f'Please choose remote-control folder with "{PRIVATE_KEYS_FOLDER}" subfolder')
                        return
                    else:
                        logging.info(f'Adding "{PRIVATE_KEYS_FOLDER}" folder')
                        request = {"command": "folder_add"}
                        if base_folder.type in (BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType):
                            prompt_msg = (
                                f'The folder "{base_folder.name}" is a shared folder. It is not recommended to have '
                                f'"{PRIVATE_KEYS_FOLDER}" in a shared folder. Create anyway?'
                            )
                            choice = user_choice(f'\n{prompt_msg}', 'yn', default='n')
                            if choice.lower() == 'n':
                                logging.warning('Please choose remote-control folder that is not a shared folder')
                                return
                            else:
                                request['folder_type'] = 'shared_folder_folder'
                        else:
                            request['folder_type'] = 'user_folder'

                        create_folder(params, base_folder, request, PRIVATE_KEYS_FOLDER)
                        logging.info('Try running command again')
                        return

                user_public_pem = params.rsa_key.public_key().exportKey(format='PEM')
                user_public_key = ''.join(user_public_pem.decode().splitlines()[1:-1])
                jwt_token = request_token(
                    params, private_key_folder, login=params.user, public_key=user_public_key, scope=['user']
                )

                logging.info('Remote user has been added')
