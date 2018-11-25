'''
Kan Yang, Xiaohua Jia

| From: Two-Factor Data Access Control With Efficient Revocation for Multi-Authority Cloud Storage Systems
| Published in:   IEEE
| Available From: https://ieeexplore.ieee.org/document/7570209
| Notes: n-of-n threshhold gate policy

* type:           ciphertext-policy attribute-based encryption (public key)
* setting:        Pairing

:Authors:   Marvin Petzolt
:Date:      11/2018
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import uuid

class TFDACMACS(object):
    def __init__(self, groupObj):
        self.util = SecretUtil(groupObj, verbose=False)
        self.group = groupObj

    def setup(self):
        '''Global Setup (executed by CA)'''
        g = self.group.random(G1)
        H = lambda x: self.group.hash(x, G1)
        GPP = {'g': g, 'H': H}
        return GPP

    def registerUser(self, GPP):
        '''Generate user keys (executed by user, signed by CA).'''
        g = GPP['g']
        uid = str(uuid.uuid4())
        sk = self.group.random()
        pk = g ** sk

        # TODO: sign sk and pk
        return {
            'uid': uid,
            'pk': None,
            'sk': None
        }

    def setupAuthority(self, GPP, authorityid, attributes):
        """Generate attribute authority keys (executed by attribute authority)"""
        # Attributes are expected to be a dict from attribute to all attribute values
        g = GPP['g']
        x = self.group.random()
        APK = pair(g, g) ** x

        # Scheme is limited in the access structure
        UPK = dict()
        USK = dict()
        PK = {
            'aid': authorityid,
            'APK': APK,
            'UPK': UPK
        }

        SK = {
            'aid': authorityid,
            'ASK': x,
            'USK': USK
        }
        for attribute, values in attributes.items():
            for value in values:
                self.registerAttribute(GPP, attribute, value, PK, SK)
        return PK, SK

    def registerAttribute(self, GPP, attribute, value, PK, SK):
        # UPK and USK also possible with call by reference
        attr_split = attribute.split(".")
        if attr_split[0] != PK['aid'] and len(attr_split) != 2:
            raise Exception("Attribute %s does not lie in the domain of %s. Expected form 'aid.attr_name'."
                            % (attribute, PK['aid']))

        UPK = PK['UPK']
        USK = SK['USK']
        if attribute not in UPK or attribute not in USK:
            UPK[attribute] = dict()
            USK[attribute] = dict()

        if value not in UPK[attribute] or value not in USK[attribute]:
            private_key = self.group.random()
            USK[attribute][value] = private_key
            UPK[attribute][value] = GPP['g'] ** private_key
        return PK, SK

    def setupDataOwner(self, GPP):
        alpha = self.group.random() # alpha
        public_key = GPP['g'] ** alpha
        oid = str(uuid.uuid4())
        OSK = {
            'oid': oid,
            'alpha': alpha
        }
        OPK = {
            'oid': oid,
            'g_alpha': public_key
        }
        return OSK, OPK

    def keygen(self, GPP, attributes, userObj, SK, PK, extend_sk = None):
        # TODO: validate users certificate

        if extend_sk is None:
            SK_uid = dict()
        else:
            SK_uid = extend_sk

        H = GPP['H']
        g = GPP['g']
        # register missing attribute values
        for attribute in attributes:
            attr_split = attribute.split(":")
            attribute_identifier = attr_split[0]
            attribute_value = attr_split[1]
            SK_uid[attribute_identifier] = dict()
            self.registerAttribute(GPP, attribute_identifier, attribute_value, PK, SK)
            SK_uid[attribute_identifier][attribute_value] = g ** SK['ASK'] * H(userObj['uid']) ** SK['USK'][attribute_identifier][attribute_value]

        return SK_uid

    def authRequest(self, GPP, userObj, OSK):
        # TODO: validate certificate
        return GPP['H'](userObj['uid']) ** OSK['alpha'] # SK_uid_oid

    def _groupByAuthorityAndCount(self, attributes, pk_authorities):
        aa_groups = dict()
        post_processed_attributes = list()

        for attribute in attributes:
            current_aid = attribute.split(".")[0]
            attr_value_split = attribute.split(":")
            attribute_identifier = attr_value_split[0]
            value = attr_value_split[1]
            assert len(attr_value_split) == 2, "Expected attribute of form 'aid.attr_name:attr_value' but was %s." % attribute
            assert current_aid in pk_authorities, "Authority %s for attribute %s not found." % (current_aid, attribute)
            assert attribute_identifier in pk_authorities[current_aid]['UPK'] and value in pk_authorities[current_aid]['UPK'][attribute_identifier], "Authority %s for attribute %s not found." % (current_aid, attribute)
            aa = pk_authorities[current_aid]

            if current_aid not in aa_groups:
                aa_groups[current_aid] = {
                    'n': 1,
                    'aa': aa
                }
            else:
                aa_groups[current_aid]['n'] += 1

            post_processed_attributes.append({
                'identifier': attribute_identifier,
                'name': attribute,
                'aid': current_aid,
                'value': value
            })

        return aa_groups, post_processed_attributes


    def encrypt(self, GPP, policy_str, m, pk_authorities, OSK):
        # executed by data owner
        # under the assumption that the attributes have the form authority_id.attr:value
        attributes = self.util.createNofNThresholdPolicy(policy_str)
        AAs, pp_attributes = self._groupByAuthorityAndCount(attributes, pk_authorities)

        g = GPP['g']
        s = self.group.random()
        C_1 = self.group.init(ZR, 1)
        C_2 = g ** s
        C_3 = self.group.init(ZR, 1)

        for aid, AA in AAs.items():
            C_1 *= AA['aa']['APK'] ** self.group.init(ZR, AA['n'])
        C_1 = m * C_1 ** s

        for attribute in pp_attributes:
            aid = attribute['aid']
            attr_id = attribute['identifier']
            attr_value = attribute['value']
            C_3 *= AAs[aid]['aa']['UPK'][attr_id][attr_value]
        C_3 **= (s + OSK['alpha'])

        label = str(uuid.uuid4())
        return {
            'oid': OSK['oid'],
            'ID_w': label,
            'W': attributes,
            'C_1': C_1,
            'C_2': C_2,
            'C_3': C_3
        }


    def decrypt(self, GPP, CT, userObj, SK_uid, SK_uid_oid, authorities):
        SK_W = self.group.init(ZR, 1)
        UPK_W = self.group.init(ZR, 1)
        for attr_policy in CT['W']:
            attr_split = attr_policy.split(":")
            attr_identifier = attr_split[0]
            attr_value = attr_split[1]
            auth_identifier = attr_identifier.split(".")[0]

            if not SK_uid[attr_identifier] or not SK_uid[attr_identifier][attr_value]:
                raise Exception("user does not fulfill policy. Missing attribute %s" % attr_policy)

            SK_W *= SK_uid[attr_identifier][attr_value]
            UPK_W *= authorities[auth_identifier]['UPK'][attr_identifier][attr_value]

        return (CT['C_1'] * pair(GPP['H'](userObj['uid']), CT['C_3'])) / (pair(CT['C_2'], SK_W) * pair(SK_uid_oid, UPK_W))


def basicTest():
    print("RUN basicTest")
    groupObj = PairingGroup('SS512')
    dac = TFDACMACS(groupObj)
    GPP = dac.setup()

    # authority registry
    authorities = {}

    # setup authority
    authorityAttributes = {
            "tuBerlin.male": ['true', 'false'],
            "tuBerlin.student": ['true', 'false']
    }
    authorityId = "tuBerlin"
    APK, ASK = dac.setupAuthority(GPP, authorityId, authorityAttributes)
    authorities[authorityId] = APK

    # register alice as the message receiver
    alice = dac.registerUser(GPP)
    aliceAttriubtes = [
        "tuBerlin.male:false",
        "tuBerlin.student:true",
    ]
    SK_alice = dac.keygen(GPP, aliceAttriubtes, alice, ASK, APK)

    # register bob as the message sender (data owner)
    OSK_bob, OPK_bob = dac.setupDataOwner(GPP)

    # register alice to bob
    DO_alice_to_bob = dac.authRequest(GPP, alice, OSK_bob)
    
    # random message
    m = groupObj.random(GT)

    # bob encrypts message
    policy_str = 'tuBerlin.male:false and tuBerlin.student:true'
    CT = dac.encrypt(GPP, policy_str, m, authorities, OSK_bob)

    # Alice decrypts message
    PT = dac.decrypt(GPP, CT, alice, SK_alice, DO_alice_to_bob, authorities)

    assert m == PT, 'FAILED DECRYPTION!'
    print('SUCCESSFUL DECRYPTION')


def basicTest_complexAttribute():
    print("RUN basicTest with complex attributes")
    groupObj = PairingGroup('SS512')
    dac = TFDACMACS(groupObj)
    GPP = dac.setup()

    # authority registry
    authorities = {}

    # setup authority with no attributes yet.
    authorityId = "tuBerlin"
    APK, ASK = dac.setupAuthority(GPP, authorityId, dict())
    authorities[authorityId] = APK

    # register alice as the message receiver
    alice = dac.registerUser(GPP)
    aliceAttriubtes = [
        "tuBerlin.email:alice@campus.tu-berlin.de"
    ]
    SK_alice = dac.keygen(GPP, aliceAttriubtes, alice, ASK, APK)

    # register bob as the message sender (data owner)
    OSK_bob, OPK_bob = dac.setupDataOwner(GPP)

    # register alice to bob
    DO_alice_to_bob = dac.authRequest(GPP, alice, OSK_bob)

    # random message
    m = groupObj.random(GT)

    # bob encrypts message
    policy_str = 'tuBerlin.email:alice@campus.tu-berlin.de'
    CT = dac.encrypt(GPP, policy_str, m, authorities, OSK_bob)

    # Alice decrypts message
    PT = dac.decrypt(GPP, CT, alice, SK_alice, DO_alice_to_bob, authorities)

    assert m == PT, 'FAILED DECRYPTION!'
    print('SUCCESSFUL DECRYPTION')


def basicTest_withMultipleAuthorities():
    print("RUN basicTest with multiple authorities")
    groupObj = PairingGroup('SS512')
    dac = TFDACMACS(groupObj)
    GPP = dac.setup()

    # authority registry
    authorities = {}

    # setup authority tuBerlin with no attributes yet.
    authorityIdTuBerlin = "tuBerlin"
    APK_TU, ASK_TU = dac.setupAuthority(GPP, authorityIdTuBerlin, dict())
    authorities[authorityIdTuBerlin] = APK_TU

    # setup authority HPI with no attributes yet.
    authorityIdHPI = "HPI"
    APK_HPI, ASK_HPI = dac.setupAuthority(GPP, authorityIdHPI, dict())
    authorities[authorityIdHPI] = APK_HPI

    # register alice as the message receiver
    alice = dac.registerUser(GPP)
    aliceAttriubtesTU = [
        "tuBerlin.email:alice@campus.tu-berlin.de"
    ]
    SK_alice = dac.keygen(GPP, aliceAttriubtesTU, alice, ASK_TU, APK_TU)
    aliceAttributesHPI = [
        "HPI.studentStatus:guest"
    ]
    SK_alice = dac.keygen(GPP, aliceAttributesHPI, alice, ASK_HPI, APK_HPI, extend_sk=SK_alice)

    # register bob as the message sender (data owner)
    OSK_bob, OPK_bob = dac.setupDataOwner(GPP)

    # register alice to bob
    DO_alice_to_bob = dac.authRequest(GPP, alice, OSK_bob)

    # random message
    m = groupObj.random(GT)

    # bob encrypts message
    policy_str = 'tuBerlin.email:alice@campus.tu-berlin.de and HPI.studentStatus:guest'
    CT = dac.encrypt(GPP, policy_str, m, authorities, OSK_bob)

    # Alice decrypts message
    PT = dac.decrypt(GPP, CT, alice, SK_alice, DO_alice_to_bob, authorities)

    assert m == PT, 'FAILED DECRYPTION!'
    print('SUCCESSFUL DECRYPTION')

if __name__ == '__main__':
    basicTest()
    basicTest_complexAttribute()
    basicTest_withMultipleAuthorities()
    # test()
