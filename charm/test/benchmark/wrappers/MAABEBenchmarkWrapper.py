import time

from charm.toolbox.pairinggroup import PairingGroup


def find_entity(entity_id, entities, entity_key_name="GID"):
    start_time = time.time()
    for entity in entities:
        if entity[entity_key_name] == entity_id:
            end_time = time.time()
            return entity, end_time - start_time
    raise Exception("Could not find entity %s." % entity_id)


class MAABEBenchmarkWrapper(object):
    DEFAULT_AUTHORITY_ID = "TUBERLIN"
    DEFAULT_USER_ID = "STUDENT1"

    def __init__(self):
        self.group = PairingGroup('SS512')

    def setup(self):
        pass

    def authsetup(self, attributes, authority_id):
        return 0

    def registerUser(self, user_id):
        pass

    def keygen(self, attributes, user_id, as_authority_id):
        return 0

    def encrypt(self, policy, message):
        return 0

    def decrypt(self, user_id):
        return 0

    def measure_setup(self):
        start_time = time.time()
        self.setup()
        end_time = time.time()
        return end_time - start_time

    def measure_authsetup(self, attributes, authority_id=DEFAULT_AUTHORITY_ID):
        start_time = time.time()
        minus = self.authsetup(attributes, authority_id)
        end_time = time.time()
        return end_time - start_time - minus

    def measure_registerUser(self, user_id=DEFAULT_AUTHORITY_ID):
        start_time = time.time()
        self.registerUser(user_id)
        end_time = time.time()
        return end_time - start_time

    def measure_keygen(self, attributes, user_id=DEFAULT_USER_ID, as_authority_id=DEFAULT_AUTHORITY_ID):
        start_time = time.time()
        minus = self.keygen(attributes, user_id, as_authority_id)
        end_time = time.time()
        return end_time - start_time - minus

    def measure_encrypt(self, policy, message):
        self.message = message
        start_time = time.time()
        minus = self.encrypt(policy, message)
        end_time = time.time()
        return end_time - start_time - minus

    def measure_decrypt(self, user_id):
        start_time = time.time()
        minus = self.decrypt(user_id)
        end_time = time.time()
        return end_time - start_time - minus
