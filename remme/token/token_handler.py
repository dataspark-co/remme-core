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
import uuid
import logging
from sawtooth_sdk.processor.exceptions import InvalidTransaction

from remme.protos.token_pb2 import (
    Account, GenesisStatus, TokenMethod, GenesisPayload, TransferPayload
)
from remme.protos.permission_pb2 import (
    PermissionMethod, Document, Access, PermissionProtocol
)
from remme.shared.basic_handler import *
from remme.shared.singleton import singleton

LOGGER = logging.getLogger(__name__)

ZERO_ADDRESS = '0' * 64

FAMILY_NAME = 'token'
FAMILY_VERSIONS = ['0.1']


@singleton
class PermissionHandler(BasicHandler):
    def __init__(self):
        super().__init__('permission', ['0.1'])
        self.zero_address = self.make_address(ZERO_ADDRESS)

    def get_state_processor(self):
        return {
            PermissionMethod.CREATE_DOCUMENT: {
                'pb_class': PermissionProtocol,
                'processor': self.create_document,
            },
            PermissionMethod.UPDATE_DOCUMENT: {
                'pb_class': PermissionProtocol,
                'processor': self.update_document,
            },
            PermissionMethod.CREATE_ACCESS: {
                'pb_class': PermissionProtocol,
                'processor': self.create_access,
            },
        }

    @staticmethod
    def _create_access_pb(pub_key, access_key=None):
        access = Access()
        access.pub_container_key = pub_key
        if access_key:
            access.access_key = access_key
        return access

    def create_document(self, context, pub_key, payload):
        address = self.make_address_from_data(pub_key)
        if self.zero_address == address:
            raise InvalidTransaction("Zero address cannot involve in any operation.")

        document = get_data(context, Document, payload.document_id)
        if document:
            raise InvalidTransaction("Document '%s' already exists." % payload.document_id)

        document = Document()
        document.id = payload.document_id
        document.data = payload.data
        document.accesses.MergeFrom(payload.accesses)

        return {
            document.id: document
        }

    def update_document(self, context, pub_key, payload):
        address = self.make_address_from_data(pub_key)
        if self.zero_address == address:
            raise InvalidTransaction("Zero address cannot involve in any operation.")

        document = get_data(context, Document, payload.document_id)
        if not document:
            raise InvalidTransaction("Document '%s' not found." % payload.document_id)

        pp = None
        for access in document.accesses:
            if access.pub_container_key == pub_key:
                pp = access.pub_container_key
                break
        if not pp:
            raise InvalidTransaction("User '%s' does not have access to update doc." %
                                     (pub_key))

        document.data = payload.data
        try:
            for i, access in enumerate(document.accesses):
                del document.accesses[i]
                i -= 1
        except Exception:
            pass

        document.accesses.MergeFrom(payload.accesses)

        return {
            document.id: document
        }

    def create_access(self, context, pub_key, payload):
        address = self.make_address_from_data(pub_key)
        if self.zero_address == address:
            raise InvalidTransaction("Zero address cannot involve in any operation.")

        document = get_data(context, Document, payload.document_id)
        if not document:
            raise InvalidTransaction("Document '%s' not found." % payload.document_id)

        for access in document.accesses:
            if access.pub_container_key == payload.grant_pub_container_key:
                raise InvalidTransaction("Document '%s' for user '%s' already grant access." %
                                         (payload.document_id, payload.grant_pub_container_key))

        document.accesses.extend([
            self._create_access_pb(payload.grant_pub_container_key)
        ])

        return {
            document.id: document
        }


# TODO: ensure receiver_account.balance += transfer_payload.amount
# is within uint64
@singleton
class TokenHandler(BasicHandler):
    def __init__(self):
        super().__init__(FAMILY_NAME, FAMILY_VERSIONS)
        self.zero_address = self.make_address(ZERO_ADDRESS)

    def get_state_processor(self):
        return {
            TokenMethod.TRANSFER: {
                'pb_class': TransferPayload,
                'processor': self._transfer
            },
            TokenMethod.GENESIS: {
                'pb_class': GenesisPayload,
                'processor': self._genesis
            }
        }

    def get_account_by_pub_key(self, context, pub_key):
        address = self.make_address_from_data(pub_key)
        account = get_data(context, Account, address)
        if account is None:
            return address, Account()
        return address, account

    def _genesis(self, context, pub_key, genesis_payload):
        signer_key, account = self.get_account_by_pub_key(context, pub_key)
        genesis_status = get_data(context, GenesisStatus, self.zero_address)
        if not genesis_status:
            genesis_status = GenesisStatus()
        elif genesis_status.status:
            raise InvalidTransaction('Genesis is already initialized.')
        genesis_status.status = True
        account = Account()
        account.balance = genesis_payload.total_supply
        LOGGER.info('Generated genesis transaction. Issued {} tokens to address {}'
                    .format(genesis_payload.total_supply, signer_key))
        return {
            signer_key: account,
            self.zero_address: genesis_status
        }

    def _transfer(self, context, pub_key, transfer_payload):
        signer_key, signer_account = self.get_account_by_pub_key(context, pub_key)
        if self.zero_address in [transfer_payload.address_to, signer_key]:
            raise InvalidTransaction("Zero address cannot involve in any operation.")
        if signer_key == transfer_payload.address_to:
            raise InvalidTransaction("Account cannot send tokens to itself.")

        receiver_account = get_data(context, Account, transfer_payload.address_to)

        if not receiver_account:
            receiver_account = Account()
        if not signer_account:
            signer_account = Account()

        if signer_account.balance < transfer_payload.value:
            raise InvalidTransaction("Not enough transferable balance. Signer's current balance: {}"
                                     .format(signer_account.balance))

        receiver_account.balance += transfer_payload.value
        signer_account.balance -= transfer_payload.value

        LOGGER.info('Transferred {} tokens from {} to {}'.format(transfer_payload.value,
                                                                 signer_key,
                                                                 transfer_payload.address_to))

        return {
            signer_key: signer_account,
            transfer_payload.address_to: receiver_account
        }
