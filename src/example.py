
from abc import ABC, abstractmethod
import cbor2
from cbor_diag import cbor2diag
from typing import Type
import unittest
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers.algorithms import AES128, AES256
from cryptography.hazmat.primitives.ciphers import BlockCipherAlgorithm
from pycose import headers, algorithms
from pycose.keys import SymmetricKey, keyops, keyparam
from pycose.messages import Mac0Message
from pycose.exceptions import CoseInvalidKey


class _CMAC(algorithms.CoseAlgorithm, ABC):
    @classmethod
    @abstractmethod
    def get_key_length(cls) -> int:
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def get_tag_length(cls) -> int:
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def cipher_cls(cls) -> Type[BlockCipherAlgorithm]:
        raise NotImplementedError()

    @classmethod
    def compute_tag(cls, key: 'SK', data: bytes) -> bytes:
        if len(key.k) != cls.get_key_length():
            raise CoseInvalidKey

        h = CMAC(cls.cipher_cls()(key.k))
        h.update(data)
        full_tag = h.finalize()

        return full_tag[:cls.get_tag_length()]

    @classmethod
    def verify_tag(cls, key: 'SK', tag: bytes, data: bytes) -> bool:

        computed_tag = cls.compute_tag(key, data)

        if tag == computed_tag:
            return True
        else:
            return False


@algorithms.CoseAlgorithm.register_attribute()
class AESCMAC128_128(_CMAC):

    identifier = 254
    fullname = "AES_CMAC_128_128"

    @classmethod
    def cipher_cls(cls) -> Type[BlockCipherAlgorithm]:
        return AES128

    @classmethod
    def get_key_length(cls) -> int:
        return 16

    @classmethod
    def get_tag_length(cls) -> int:
        return 16


@algorithms.CoseAlgorithm.register_attribute()
class AESCMAC256_128(_CMAC):

    identifier = 255
    fullname = "AES_CMAC_256_128"

    @classmethod
    def cipher_cls(cls) -> Type[BlockCipherAlgorithm]:
        return AES256

    @classmethod
    def get_key_length(cls) -> int:
        return 32

    @classmethod
    def get_tag_length(cls) -> int:
        return 16


class TestExample(unittest.TestCase):

    def test_CMAC128(self):
        print()

        # Augmented from RFC 9172 example
        # https://github.com/cose-wg/Examples/blob/master/cbc-mac-examples/cbc-mac-02.json
        key = SymmetricKey(
            k=bytes.fromhex('849B57219DAE48DE646D07DBB533566E'),
            optional_params={
                keyparam.KpKid: b'secret128',
                keyparam.KpAlg: AESCMAC128_128,
                keyparam.KpKeyOps: [keyops.MacCreateOp, keyops.MacVerifyOp],
            }
        )
        print('Key: {}'.format(cbor2diag(key.encode())))

        msg_obj = Mac0Message(
            phdr={
                headers.Algorithm: key.alg,
            },
            uhdr={
                headers.KID: key.kid,
            },
            payload=b'This is the content.',
            # Non-encoded parameters
            external_aad=b'',
        )
        msg_obj.key = key

        # COSE internal structure
        cose_struct_enc = msg_obj._mac_structure
        print('COSE Structure: {}'.format(cbor2diag(cose_struct_enc)))
        print('Encoded: {}'.format(cose_struct_enc.hex()))

        # Encoded message
        message_enc = msg_obj.encode(tag=True)
        print('Message: {}'.format(cbor2diag(message_enc)))
        print('Encoded: {}'.format(message_enc.hex()))

    def test_CMAC256(self):
        print()

        # Augmented from RFC 9172 example
        # https://github.com/cose-wg/Examples/blob/master/cbc-mac-examples/cbc-mac-04.json
        key = SymmetricKey(
            k=bytes.fromhex('849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188'),
            optional_params={
                keyparam.KpKid: b'secret256',
                keyparam.KpAlg: AESCMAC256_128,
                keyparam.KpKeyOps: [keyops.MacCreateOp, keyops.MacVerifyOp],
            }
        )
        print('Key: {}'.format(cbor2diag(key.encode())))

        msg_obj = Mac0Message(
            phdr={
                headers.Algorithm: key.alg,
            },
            uhdr={
                headers.KID: key.kid,
            },
            payload=b'This is the content.',
            # Non-encoded parameters
            external_aad=b'',
        )
        msg_obj.key = key

        # COSE internal structure
        cose_struct_enc = msg_obj._mac_structure
        print('COSE Structure: {}'.format(cbor2diag(cose_struct_enc)))
        print('Encoded: {}'.format(cose_struct_enc.hex()))

        # Encoded message
        message_enc = msg_obj.encode(tag=True)
        print('Message: {}'.format(cbor2diag(message_enc)))
        print('Encoded: {}'.format(message_enc.hex()))
