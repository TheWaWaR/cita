#!/usr/bin/env python  
# coding=utf-8  

import argparse
import json
import os
import time
from os import path
import binascii
import hashlib
import sys

from ethereum.tools.tester import (Chain, get_env)
from ethereum.tools._solidity import (
    get_solidity,
    compile_file,
    solidity_get_contract_data,
)
from ethereum.abi import ContractTranslator

SOLIDITY_AVAILABLE = get_solidity() is not None
CONTRACTS_DIR = path.join(path.dirname(__file__), os.pardir, 'contracts')

CONTRACTS = {
    '0x00000000000000000000000000000000013241a2': {'file': 'system/node_manager.sol',
                                                   'name': 'NodeManager'},
    '0x00000000000000000000000000000000013241a3': {'file': 'system/quota_manager.sol',
                                                   'name': 'QuotaManager'},
    '0x00000000000000000000000000000000013241a4': {'file': 'system/permission_manager.sol',
                                                   'name': 'PermissionManager'},
    '0x00000000000000000000000000000000013241a5': {'file': 'permission/permission_system.sol',
                                                   'name': 'PermissionSystem'},
    '0x0000000000000000000000000000000031415926': {'file': 'system/param_constant.sol',
                                                   'name': 'ParamConstant'},
    '0x00000000000000000000000000000000013241b2': {'file': 'permission_management/permission_management.sol',
                                                   'name': 'PermissionManagement'},
    '0x00000000000000000000000000000000013241b3': {'file': 'permission_management/permission_creator.sol',
                                                   'name': 'PermissionCreator'},
    '0x00000000000000000000000000000000013241b4': {'file': 'permission_management/authorization.sol',
                                                   'name': 'Authorization'},
    '0x00000000000000000000000000000000013241b5': {'file': 'permission_management/permission.sol',
                                                   'name': 'Permission'},
    '0xe9e2593c7d1db5ee843c143e9cb52b8d996b2380': {'file': 'permission_management/role_creator.sol',
                                                   'name': 'RoleCreator'},
    '0xe3b5ddb80addb513b5c981e27bb030a86a8821ee': {'file': 'permission_management/role_management.sol',
                                                   'name': 'RoleManagement'}
}

def init_contracts(nodes):
    result = dict()
    env = get_env(None)
    env.config['BLOCK_GAS_LIMIT'] = 471238800
    tester_state = Chain(env=env)

    for address, contract in CONTRACTS.iteritems():
        contract_path = path.join(CONTRACTS_DIR, contract['file'])
        simple_compiled = compile_file(contract_path)
        simple_data = solidity_get_contract_data(
            simple_compiled,
            contract_path,
            contract['name'],
        )

        if '' == simple_data['bin']:
            sys.exit()

        ct = ContractTranslator(simple_data['abi'])

        if address == '0x00000000000000000000000000000000013241a3' or address == '0x00000000000000000000000000000000013241b4':
            extra = (ct.encode_constructor_arguments([nodes[address]]) if nodes[address] else b'')
        elif address == '0x0000000000000000000000000000000031415926':
            extra = (ct.encode_constructor_arguments([nodes[address][0], nodes[address][1], nodes[address][2]]) if nodes[address] else b'')
        elif address == '0x00000000000000000000000000000000013241a2' or address == '0x00000000000000000000000000000000013241a4' or address == '0x00000000000000000000000000000000013241a5':
            extra = (ct.encode_constructor_arguments([nodes[address][0], nodes[address][1]]) if nodes[address] else b'')
        elif address == '0x00000000000000000000000000000000013241b5':
            for addr, permission in nodes[address].iteritems():
                new_funcs = []
                for func in permission[2]:
                    new_func = ''
                    for i in range(0, len(func), 2):
                        new_func += chr((int(func[i:i+2], 16)))
                    new_funcs.append(new_func)

                extra = (ct.encode_constructor_arguments([permission[0], permission[1], new_funcs]))

                if addr != '0x00000000000000000000000000000000013241b5':
                    abi_address = tester_state.contract(simple_data['bin'] + extra, language='evm', startgas=30000000)
                    tester_state.mine()
                    account = tester_state.chain.state.account_to_dict(abi_address)
                    result[addr] = {'code': account['code'], 'storage': account['storage'], 'nonce': account['nonce']}
        else:
            extra = ''

        # print(binascii.hexlify(simple_data['bin'] + extra))
        print "contract:\n", contract['name']
        print "extra:\n", binascii.hexlify(extra)
        abi_address = tester_state.contract(simple_data['bin'] + extra, language='evm', startgas=30000000)
        tester_state.mine()
        account = tester_state.chain.state.account_to_dict(abi_address)
        result[address] = {'code': account['code'], 'storage': account['storage'], 'nonce': account['nonce']}

    return result


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--authorities", help="Authorities nodes list file.")
    parser.add_argument(
        "--init_data", help="init with constructor_arguments.")
    parser.add_argument(
        "--resource", help="chain resource folder.")

    args = parser.parse_args()
    init_path = os.path.join(args.init_data)
    auth_path = os.path.join(args.authorities)
    res_path = os.path.join(args.resource)

    authorities = []
    with open(auth_path, "r") as f:
        for line in f:
            authorities.append(line.strip('\n'))

    init_data = dict()

    with open(init_path, "r") as f:
        init_data = json.load(f)

    for auth in authorities:
        init_data["0x00000000000000000000000000000000013241a2"][0].append(auth)

    data = dict()
    timestamp = int(time.time())
    if os.path.exists(res_path) and os.path.isdir(res_path):
        #file list make sure same order when calc hash
        file_list = ""
        res_path_len = len(res_path)
        md5obj = hashlib.md5()
        for root, dirs, files in os.walk(res_path, True):
            for name in files:
                filepath = os.path.join(root, name)
                with open(filepath,'rb') as f:
                    md5obj.update(f.read())
                    file_list += filepath[res_path_len:] + "\n"
        res_hash = md5obj.hexdigest()

        file_list_path = os.path.join(res_path, "file_list")
        with open(file_list_path,'w') as f:
            f.write(file_list)
        data["prevhash"] = "0x00000000000000000000000000000000" + res_hash
    else:
        data["prevhash"] = "0x0000000000000000000000000000000000000000000000000000000000000000"
    data["timestamp"] = timestamp

    print "init data\n", json.dumps(init_data, indent=4)
    alloc = init_contracts(init_data)
    data['alloc'] = alloc
    dump_path =  "genesis.json"
    with open(dump_path, "w") as f:
        json.dump(data, f, indent=4)

if __name__ == '__main__':
    main()
