# Copyright 2018 REMME
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------

import json
import logging

from remme.protos.token_pb2 import TokenMethod, GenesisPayload, TransferPayload
from remme.protos.permission_pb2 import PermissionMethod, PermissionProtocol
from remme.shared.basic_client import BasicClient
from remme.token.token_handler import TokenHandler, PermissionHandler
from remme.protos.transaction_pb2 import TransactionPayload

from remme.protos.token_pb2 import Account
from remme.protos.permission_pb2 import Document, Access


log = logging.getLogger('werkzeug')
log.setLevel(logging.DEBUG)


class PermissionClient(BasicClient):
    def __init__(self):
        super().__init__(PermissionHandler)

    def get_document(self, document_id, storage=None):
        document = Document()
        if storage is None:
            storage = self
        document.ParseFromString(storage.get_value(document_id))
        return document

    def get_access_list(self, document_id, storage=None):
        document = Document()
        if storage is None:
            storage = self
        document.ParseFromString(storage.get_value(document_id))
        return document.accesses

    def create_document(self, pub_container_key, document_id, data, access_key, storage=None):
        if storage is None:
            storage = self
        proto = PermissionProtocol(
            document_id=document_id,
            data=data,
            pub_container_key=pub_container_key,
            access_key=access_key,
        )
        tr = self._send_transaction(PermissionMethod.CREATE_DOCUMENT, proto, [self.make_address_from_data(self._signer.get_public_key().as_hex())], storage)
        return tr

    def update_document(self, pub_container_key, document_id, data, access_list, storage=None):
        if storage is None:
            storage = self
        proto = PermissionProtocol(
            document_id=document_id,
            data=data,
            pub_container_key=pub_container_key,
            accesses=[
                Access(pub_container_key=access['pub_container_key'],
                       access_key=access['access_key'])
                for access in access_list
            ],
        )
        tr = self._send_transaction(PermissionMethod.UPDATE_DOCUMENT, proto, [self.make_address_from_data(self._signer.get_public_key().as_hex())], storage)
        return tr

    def create_access(self, pub_container_key, document_id, grant_pub_container_key, storage=None):
        if storage is None:
            storage = self
        proto = PermissionProtocol(
            document_id=document_id,
            pub_container_key=pub_container_key,
            grant_pub_container_key=grant_pub_container_key,
        )
        tr = self._send_transaction(PermissionMethod.CREATE_ACCESS, proto, [self.make_address_from_data(self._signer.get_public_key().as_hex())], storage)
        return tr

    def _send_transaction(self, method, data, addresses, storage=None):
        log.error(storage.handler)
        if storage is not None and storage != self:
            handler = storage.handler

            trans = TransactionPayload()
            trans.method = method
            trans.data = data.SerializeToString()
            handler.apply_local(trans, storage)
            return data
        return super()._send_transaction(method, data, addresses)


class TokenClient(BasicClient):
    def __init__(self):
        super().__init__(TokenHandler)

    def _send_transaction(self, method, data_pb, extra_addresses_input_output):
        addresses_input_output = [self.make_address_from_data(self._signer.get_public_key().as_hex())]
        if extra_addresses_input_output:
            addresses_input_output += extra_addresses_input_output
        return super()._send_transaction(method, data_pb, addresses_input_output)

    @classmethod
    def get_transfer_payload(self, address_to, value):
        transfer = TransferPayload()
        transfer.address_to = address_to
        transfer.value = value

        return transfer

    @classmethod
    def get_genesis_payload(self, total_supply):
        genesis = GenesisPayload()
        genesis.total_supply = int(total_supply)

        return genesis

    @classmethod
    def get_account_model(self, balance):
        account = Account()
        account.balance = int(balance)

        return account

    def transfer(self, address_to, value):
        extra_addresses_input_output = [address_to]
        transfer = self.get_transfer_payload(address_to, value)

        status = self._send_transaction(TokenMethod.TRANSFER, transfer, extra_addresses_input_output)

        return json.loads(status)

    def get_account(self, address):
        account = Account()
        account.ParseFromString(self.get_value(address))
        return account

    def get_balance(self, address):
        account = self.get_account(address)
        return account.balance
