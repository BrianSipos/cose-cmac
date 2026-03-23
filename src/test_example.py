
from abc import ABC, abstractmethod

from cbor_diag import cbor2diag
import logging
import unittest
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers.algorithms import AES, AES128, AES256
from pycose import headers, algorithms
from pycose.keys import SymmetricKey, keyops, keyparam
from pycose.messages import CoseMessage, Mac0Message
from pycose.exceptions import CoseException, CoseInvalidKey


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
    def cipher_cls(cls) -> type[AES]:
        raise NotImplementedError()

    @classmethod
    def compute_tag(cls, key: 'SymmetricKey', data: bytes) -> bytes:
        if len(key.k) != cls.get_key_length():
            raise CoseInvalidKey

        h = CMAC(cls.cipher_cls()(key.k))
        h.update(data)
        full_tag = h.finalize()

        return full_tag[:cls.get_tag_length()]

    @classmethod
    def verify_tag(cls, key: 'SymmetricKey', tag: bytes, data: bytes) -> bool:

        computed_tag = cls.compute_tag(key, data)

        if tag == computed_tag:
            return True
        else:
            return False


@algorithms.CoseAlgorithm.register_attribute()
class AESCMAC128_64(_CMAC):

    identifier = 252
    fullname = "AES_CMAC_128_64"

    @classmethod
    def cipher_cls(cls) -> type[AES]:
        return AES128

    @classmethod
    def get_key_length(cls) -> int:
        return 16

    @classmethod
    def get_tag_length(cls) -> int:
        return 8


@algorithms.CoseAlgorithm.register_attribute()
class AESCMAC256_64(_CMAC):

    identifier = 253
    fullname = "AES_CMAC_256_64"

    @classmethod
    def cipher_cls(cls) -> type[AES]:
        return AES256

    @classmethod
    def get_key_length(cls) -> int:
        return 32

    @classmethod
    def get_tag_length(cls) -> int:
        return 8


@algorithms.CoseAlgorithm.register_attribute()
class AESCMAC128_128(_CMAC):

    identifier = 254
    fullname = "AES_CMAC_128_128"

    @classmethod
    def cipher_cls(cls) -> type[AES]:
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
    def cipher_cls(cls) -> type[AES]:
        return AES256

    @classmethod
    def get_key_length(cls) -> int:
        return 32

    @classmethod
    def get_tag_length(cls) -> int:
        return 16


LOGGER = logging.getLogger(__name__)

class TestExample(unittest.TestCase):

    def test_CMAC128(self):
        for alg in {AESCMAC128_64, AESCMAC128_128}:
            with self.subTest(str(alg)):
                LOGGER.info('Using alg %s', alg.fullname)
                # Augmented from RFC 9172 example
                # https://github.com/cose-wg/Examples/blob/master/cbc-mac-examples/cbc-mac-02.json
                key = SymmetricKey(
                    k=bytes.fromhex('849B57219DAE48DE646D07DBB533566E'),
                    optional_params={
                        keyparam.KpKid: b'secret128',
                        keyparam.KpAlg: alg,
                        keyparam.KpKeyOps: [keyops.MacCreateOp, keyops.MacVerifyOp],
                    }
                )
                LOGGER.info('Key: %s', cbor2diag(key.encode()))
        
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
                LOGGER.info('COSE Structure: %s', cbor2diag(cose_struct_enc))
                LOGGER.info('Encoded: %s', cose_struct_enc.hex())
        
                # Encoded message
                message_enc = msg_obj.encode(tag=True)
                LOGGER.info('Message: %s', cbor2diag(message_enc))
                LOGGER.info('Encoded: %s', message_enc.hex())

                # Verify from endoded form
                msg_back = CoseMessage.decode(message_enc)
                self.assertIsInstance(msg_back, Mac0Message)
                with self.assertRaises(CoseException):
                    msg_back.verify_tag()
                msg_back.key = key
                msg_back.verify_tag()

    def test_CMAC256(self):
        for alg in {AESCMAC256_64, AESCMAC256_128}:
            with self.subTest(str(alg)):
                LOGGER.info('Using alg %s', alg.fullname)
                # Augmented from RFC 9172 example
                # https://github.com/cose-wg/Examples/blob/master/cbc-mac-examples/cbc-mac-04.json
                key = SymmetricKey(
                    k=bytes.fromhex('849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188'),
                    optional_params={
                        keyparam.KpKid: b'secret256',
                        keyparam.KpAlg: alg,
                        keyparam.KpKeyOps: [keyops.MacCreateOp, keyops.MacVerifyOp],
                    }
                )
                LOGGER.info('Key: %s', cbor2diag(key.encode()))
        
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
                LOGGER.info('COSE Structure: %s', cbor2diag(cose_struct_enc))
                LOGGER.info('Encoded: %s', cose_struct_enc.hex())
        
                # Encoded message
                message_enc = msg_obj.encode(tag=True)
                LOGGER.info('Message: %s', cbor2diag(message_enc))
                LOGGER.info('Encoded: %s', message_enc.hex())

                # Verify from endoded form
                msg_back = CoseMessage.decode(message_enc)
                self.assertIsInstance(msg_back, Mac0Message)
                with self.assertRaises(CoseException):
                    msg_back.verify_tag()
                msg_back.key = key
                msg_back.verify_tag()
