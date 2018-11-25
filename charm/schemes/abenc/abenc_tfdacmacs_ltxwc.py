'''
XIAOYU LI, SHAOHUA TANG, LINGLING XU, HUAQUN WANG, AND JIE CHEN

| From: Two-Factor Data Access Control With Efficient Revocation for Multi-Authority Cloud Storage Systems
| Published in:   IEEE
| Available From: https://ieeexplore.ieee.org/document/7570209
| Notes: n-of-n threshhold gate policy, extended scheme so that 2FA can be disabled if needed

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
    ERROR_ATTR_MSG = lambda attr : "Expected attribute of form 'aid.attr_name:attr_value' but was %s." % attr

    def __init__(self, groupObj):
        self.util = SecretUtil(groupObj, verbose=False)
        self.group = groupObj

    def setup(self):
        '''Global Setup (executed by CA)'''
        g = self.group.random(G1)
        H = lambda x: self.group.hash(x, G1)
        GPP = {'g': g, 'H': H}
        return GPP


    def _extractAttributeComponents(self, attribute):
        assert type(attribute) == str
        assert ":" in attribute and "." in attribute, self.ERROR_ATTR_MSG(attribute)

        attr_identifier_value_split = attribute.split(":")
        assert len(attr_identifier_value_split) == 2, self.ERROR_ATTR_MSG(attribute)
        attr_identifier = attr_identifier_value_split[0]
        attr_value = attr_identifier_value_split[1]

        attr_aid_name_split = attr_identifier.split(".")
        assert len(attr_aid_name_split) == 2, self.ERROR_ATTR_MSG(attribute)
        return {
            'aid': attr_aid_name_split[0],
            'name': attr_aid_name_split[1],
            'id': attr_identifier,
            'value': attr_value
        }


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
            attr_obj = self._extractAttributeComponents(attribute)
            current_aid = attr_obj['aid']
            assert current_aid in pk_authorities, "Authority %s for attribute %s not found." % (current_aid, attribute)
            assert attr_obj['id'] in pk_authorities[current_aid]['UPK'] and attr_obj['value'] in pk_authorities[current_aid]['UPK'][attr_obj['id']], "Authority %s for attribute %s not found." % (current_aid, attribute)
            aa = pk_authorities[current_aid]

            if current_aid not in aa_groups:
                aa_groups[current_aid] = {
                    'n': 1,
                    'aa': aa
                }
            else:
                aa_groups[current_aid]['n'] += 1

            post_processed_attributes.append(attr_obj)

        return aa_groups, post_processed_attributes


    def encrypt(self, GPP, policy_str, m, pk_authorities, OSK = None):
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
            attr_id = attribute['id']
            attr_value = attribute['value']
            C_3 *= AAs[aid]['aa']['UPK'][attr_id][attr_value]
        C_3 **= s + OSK['alpha'] if OSK is not None else s

        label = str(uuid.uuid4())
        return {
            'oid': OSK['oid'] if OSK is not None else None,
            'ID_w': label,
            'W': attributes,
            'C_1': C_1,
            'C_2': C_2,
            'C_3': C_3
        }


    def decrypt(self, GPP, CT, userObj, SK_uid, authorities, twoFA_key = None):
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

        if twoFA_key is not None:
            return (CT['C_1'] * pair(GPP['H'](userObj['uid']), CT['C_3'])) \
                   / (pair(CT['C_2'], SK_W) * pair(twoFA_key, UPK_W))
        else:
            return (CT['C_1'] * pair(GPP['H'](userObj['uid']), CT['C_3'])) / pair(CT['C_2'], SK_W)

    def keyUpdate(self, GPP, attribute, ASK, APK, OPK, CTs, nonRevokedUsers):
        """
        Run by AA. Generates The key update key for users.
        :param GPP: global public parameters
        :param attribute: attribute string in the form of "authId.attrId:value" the attribute value to revoke
        :param ASK: secret key of AA
        :param ASK: public key of AA. This will be updated
        :param OPK: data owners public key
        :param CTs: list of all cipher texts related to the revoked attribute u
        :param nonRevokedUsers: list of non revoked userObjects
        :return: KUK: dict of userIds to key update keys and CUK: dict of ciphertext ids to cipher text update keys
                 ASK: the updates authority secret key and APK: the update authority public key
        """
        attr_obj = self._extractAttributeComponents(attribute)
        y_old = ASK['USK'][attr_obj['id']][attr_obj['value']]
        y_new = self.group.random()
        y_delta = y_new - y_old
        g = GPP['g']
        H = GPP['H']
        UPK_new = g ** y_new

        KUK = dict() # user id to update key
        for nonRevokedUser in nonRevokedUsers:
            # TODO: filter for users that actually own the attr that will be revoked
            # no security implication, rather then a performance boost
            uid = nonRevokedUser['uid']
            KUK[uid] = H(uid) ** y_delta

        CUK = dict() # label (ID_w) to cipher text update key
        for ct in CTs:
            if ct['oid'] is not None:
                CUK[ct['ID_w']] = (ct['C_2'] * OPK['g_alpha']) ** y_delta
            else:
                CUK[ct['ID_w']] = ct['C_2'] ** y_delta

        # update secret keys of authority
        ASK['USK'][attr_obj['id']][attr_obj['value']] = y_new
        APK['UPK'][attr_obj['id']][attr_obj['value']] = UPK_new

        # keep first, send KUK to respective user and CUK to CSP
        return KUK, CUK, ASK, APK


    def skUpdate(self, SKU, kuk, attribute):
        """
        Run by user.
        :param SKU: The secret key chain of the user
        :param kuk: the key update key for the given attribute
        :param attribute: the attribute to update
        :return: the update SKU
        """
        attr_obj = self._extractAttributeComponents(attribute)
        sku_old = SKU[attr_obj['id']][attr_obj['value']]
        sk_new = sku_old * kuk
        SKU[attr_obj['id']][attr_obj['value']] = sk_new
        return SKU

    def ctaUpdate(self, GPP, cuk, ct, pk_authorities):
        """
        Run by CSP
        :param cuk: the update key for the ct
        :param ct: the cipher text that will be updated
        :return: the updated cipher text
        """
        AAs, pp_attributes = self._groupByAuthorityAndCount(ct['W'], pk_authorities)

        g = GPP['g']
        r = self.group.random()
        C_1 = self.group.init(ZR, 1)
        C_2 = ct['C_2'] * g ** r
        C_3 = self.group.init(ZR, 1)

        for aid, AA in AAs.items():
            C_1 *= AA['aa']['APK'] ** self.group.init(ZR, AA['n'])
        C_1 = ct['C_1'] * C_1 ** r

        for attribute in pp_attributes:
            aid = attribute['aid']
            attr_id = attribute['id']
            attr_value = attribute['value']
            # don't need to filter here since we update already the APK
            C_3 *= AAs[aid]['aa']['UPK'][attr_id][attr_value]

        C_3 = ct['C_3'] * cuk * C_3 ** r
        ct['C_1'] = C_1
        ct['C_2'] = C_2
        ct['C_3'] = C_3
        return ct


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
    PT = dac.decrypt(GPP, CT, alice, SK_alice, authorities, twoFA_key=DO_alice_to_bob)

    assert m == PT, 'FAILED DECRYPTION!'
    print('SUCCESSFUL DECRYPTION')

    return dac, GPP, authorities, APK, ASK, alice, aliceAttriubtes, SK_alice, OPK_bob, DO_alice_to_bob, m, CT


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
    PT = dac.decrypt(GPP, CT, alice, SK_alice, authorities, twoFA_key=DO_alice_to_bob)

    assert m == PT, 'FAILED DECRYPTION!'
    print('SUCCESSFUL DECRYPTION')

    return dac, GPP, authorities, APK, ASK, alice, aliceAttriubtes, SK_alice, OPK_bob, DO_alice_to_bob, m, CT


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
    PT = dac.decrypt(GPP, CT, alice, SK_alice, authorities, twoFA_key=DO_alice_to_bob)

    assert m == PT, 'FAILED DECRYPTION!'
    print('SUCCESSFUL DECRYPTION')

    return dac, GPP, authorities, APK_HPI, ASK_HPI, alice, aliceAttributesHPI, SK_alice, OPK_bob, DO_alice_to_bob, m, CT


def basicTest_withput2FA():
    print("RUN basicTest without 2FA")
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

    # random message
    m = groupObj.random(GT)

    # bob encrypts message
    policy_str = 'tuBerlin.email:alice@campus.tu-berlin.de'
    CT = dac.encrypt(GPP, policy_str, m, authorities)

    # Alice decrypts message
    PT = dac.decrypt(GPP, CT, alice, SK_alice, authorities)

    assert m == PT, 'FAILED DECRYPTION!'
    print('SUCCESSFUL DECRYPTION')

    return dac, GPP, authorities, APK, ASK, alice, aliceAttriubtes, SK_alice, None, None, m, CT


def revocationTest(dac, GPP, authorities, APK, ASK, alice, aliceAttriubtes, SK_alice, OPK_bob, DO_alice_to_bob, m, CT):
    attrToRevoke = aliceAttriubtes[0]
    print("Revoking: ", attrToRevoke)

    # authority that issued the revoked attribute generates the update keys.
    KUK, CUK, ASK, APK = dac.keyUpdate(GPP, attrToRevoke, ASK, APK, OPK_bob, [ CT ], [ alice ])

    for uid, kuk in KUK.items():
        assert uid == alice['uid']
        # update alice key
        SK_alice = dac.skUpdate(SK_alice, kuk, attrToRevoke)

    for id_w, cuk in CUK.items():
        assert id_w == CT['ID_w']
        # CSP updates chiphertext
        CT = dac.ctaUpdate(GPP, cuk, CT, authorities)

    # Alice decrypts message
    PT = dac.decrypt(GPP, CT, alice, SK_alice, authorities, twoFA_key=DO_alice_to_bob)

    print("m", m)
    print("PT", PT)

    assert m == PT, 'FAILED DECRYPTION!'
    print('SUCCESSFUL DECRYPTION')


if __name__ == '__main__':
    basicTest()
    basicTest_complexAttribute()
    basicTest_withMultipleAuthorities()
    basicTest_withput2FA()

    revocationTest(basicTest)
    revocationTest(basicTest_complexAttribute)
    revocationTest(basicTest_withMultipleAuthorities)
    revocationTest(basicTest_withput2FA)

