import unittest

from charm.schemes.abenc.abenc_maabe_lw14 import CPabe_LW14
from charm.toolbox.pairinggroup import PairingGroup, GT

debug = True

class CPabe_LW14_test(unittest.TestCase):
    def testCPabeBasic1(self):
        # Get the eliptic curve with the bilinear mapping feature needed.
        groupObj = PairingGroup('SS512')

        cpabe = CPabe_LW14(groupObj)
        (pp, mk) = cpabe.setup()
        pol = '((ONE or THREE) and (TWO or FOUR))'
        attr_list = ['THREE', 'FIVE', 'TWO']

        if debug: print('Acces Policy: %s' % pol)
        if debug: print('User credential list: %s' % attr_list)
        m = groupObj.random(GT)

        cpkey = cpabe.keygen(pp, mk, attr_list)
        if debug: print("\nSecret key: %s" % attr_list)
        if debug: groupObj.debug(cpkey)
        cipher = cpabe.encrypt(pp, m, pol)

        if debug: print("\nCiphertext...")
        if debug: groupObj.debug(cipher)
        orig_m = cpabe.decrypt(pp, cpkey, cipher)

        assert m == orig_m, 'FAILED Decryption!!!'
        if debug: print('Successful Decryption!')
        del groupObj

    def testCPabeBasic2(self):
        # Get the eliptic curve with the bilinear mapping feature needed.
        groupObj = PairingGroup('SS512')

        cpabe = CPabe_LW14(groupObj)
        (pp, mk) = cpabe.setup()
        pol = '((ONE or THREE) and (TWO or THREE))'
        attr_list = ['THREE', 'ONE']

        if debug: print('Acces Policy: %s' % pol)
        if debug: print('User credential list: %s' % attr_list)
        m = groupObj.random(GT)

        cpkey = cpabe.keygen(pp, mk, attr_list)

        if debug: print("\nSecret key: %s" % attr_list)
        if debug: groupObj.debug(cpkey)
        cipher = cpabe.encrypt(pp, m, pol)

        if debug: print("\nCiphertext...")
        if debug: groupObj.debug(cipher)
        orig_m = cpabe.decrypt(pp, cpkey, cipher)

        assert m == orig_m, 'FAILED Decryption!!!'
        if debug: print('Successful Decryption!')
        del groupObj

    def testCPabeBasic3(self):
        # Get the eliptic curve with the bilinear mapping feature needed.
        groupObj = PairingGroup('SS512')

        cpabe = CPabe_LW14(groupObj)
        (pp, mk) = cpabe.setup()
        pol = '(((ONE or THREE) and (TWO or THREE))) and (FIVE and (SIX or SEVEN))'
        attr_list = ['THREE', 'ONE', 'FIVE', 'SEVEN']

        if debug: print('Acces Policy: %s' % pol)
        if debug: print('User credential list: %s' % attr_list)
        m = groupObj.random(GT)

        cpkey = cpabe.keygen(pp, mk, attr_list)

        if debug: print("\nSecret key: %s" % attr_list)
        if debug: groupObj.debug(cpkey)
        cipher = cpabe.encrypt(pp, m, pol)

        if debug: print("\nCiphertext...")
        if debug: groupObj.debug(cipher)
        orig_m = cpabe.decrypt(pp, cpkey, cipher)

        assert m == orig_m, 'FAILED Decryption!!!'
        if debug: print('Successful Decryption!')
        del groupObj

    @unittest.skip("currently not working")
    def testCPabeRevocation(self):
        """
        Revocation crreutnly not working.
        :return:
        """

        # Get the eliptic curve with the bilinear mapping feature needed.
        groupObj = PairingGroup('SS512')

        cpabe = CPabe_LW14(groupObj)
        (pp, mk) = cpabe.setup()
        pol = '((ONE or THREE) and (TWO or THREE))'
        attr_list = ['THREE', 'ONE']

        if debug: print('Acces Policy: %s' % pol)
        if debug: print('User credential list: %s' % attr_list)
        m = groupObj.random(GT)

        cpkey0 = cpabe.keygen(pp, mk, attr_list)
        cpkey1 = cpabe.keygen(pp, mk, attr_list)


        if debug: print("\nSecret key: %s" % attr_list)
        if debug: groupObj.debug(cpkey1)
        cipher = cpabe.encrypt(pp, m, pol, R = [0])

        if debug: print("\nCiphertext...")
        if debug: groupObj.debug(cipher)
        orig_m0 = cpabe.decrypt(pp, cpkey0, cipher, user_index=0)
        orig_m1 = cpabe.decrypt(pp, cpkey1, cipher, user_index=1)

        assert m != orig_m0, 'FAILED Revocation!!!'
        assert m == orig_m1, 'FAILED Decryption!!!'
        if debug: print('Successful Decryption with Revocation')
        del groupObj


if __name__ == "__main__":
    unittest.main()
