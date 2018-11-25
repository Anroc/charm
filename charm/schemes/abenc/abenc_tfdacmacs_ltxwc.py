'''
Kan Yang, Xiaohua Jia

| From: DAC-MACS: Effective Data Access Control for Multi-Authority Cloud Storage Systems
| Published in:  Security for Cloud Storage Systems  - SpringerBriefs in Computer Science 2014
| Available From: http://link.springer.com/chapter/10.1007/978-1-4614-7873-7_4
| Notes:

* type:           ciphertext-policy attribute-based encryption (public key)
* setting:        Pairing

:Authors:   artjomb
:Date:      07/2014
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import uuid

class TFDACMACS(object):
    def __init__(self, groupObj):
        self.util = SecretUtil(groupObj, verbose=False)  # Create Secret Sharing Scheme
        self.group = groupObj  #:Prime order group

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
        # TODO: include, but currently not used...
        # sk = self.group.random()
        # pk = g ** sk

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

    def keygen(self, GPP, attributes, userObj, SK, PK):
        '''Generate user keys for a specific attribute (executed on attribute authority)'''
        # TODO: validate users certificate

        H = GPP['H']
        g = GPP['g']
        SK_uid = dict()
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
            assert value in pk_authorities[current_aid]['UPK'][attribute_identifier], "Authority %s for attribute %s not found." % (current_aid, attribute)
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


    def decrypt(self, GPP, CT, userObj, SK_uid, SK_uid_oid, APK):
        SK_W = self.group.init(ZR, 1)
        UPK_W = self.group.init(ZR, 1)
        for attr_policy in CT['W']:
            attr_split = attr_policy.split(":")
            attr_identifier = attr_split[0]
            attr_value = attr_split[1]

            if not SK_uid[attr_identifier] or not SK_uid[attr_identifier][attr_value]:
                raise Exception("user does not fulfill policy. Missing attribute %s" % attr_policy)

            SK_W *= SK_uid[attr_identifier][attr_value]
            UPK_W *= APK['UPK'][attr_identifier][attr_value]

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
    PT = dac.decrypt(GPP, CT, alice, SK_alice, DO_alice_to_bob, APK)

    print("M:", m)
    print("PT:", PT)

    assert m == PT, 'FAILED DECRYPTION!'
    print('SUCCESSFUL DECRYPTION')


def test():
    groupObj = PairingGroup('SS512')
    # k = groupObj.random()
    # print "k", k, ~k, k * ~k
    # g = groupObj.random(G1)
    # print "g", g, pair(g, g)
    # gt = groupObj.random(GT)
    # print "gt", gt


if __name__ == '__main__':
    basicTest()
    # test()
