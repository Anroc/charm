import unittest
import time
import sys

from charm.schemes.abenc.abenc_lsw08 import KPabe
from charm.schemes.abenc.abenc_unmcpabe_yahk14 import CPABE_YAHK14
from charm.schemes.abenc.abenc_lw14 import CPabe_LW14
from charm.toolbox.pairinggroup import PairingGroup, GT

import matplotlib.pyplot as plt
import numpy as np

groups = [PairingGroup('SS512'),  PairingGroup('SS512'),  PairingGroup('SS512')]
testclasses = [KPabe(groups[0]), CPABE_YAHK14(groups[1]), CPabe_LW14(groups[2])]
setup = [tc.setup() for tc in testclasses]
keygen = [tc.keygen(setup[i][0], setup[i][1], ['1', '2', '3'] if i != 0 else '1 and 2 and 3') for i, tc in enumerate(testclasses)]
message = [group.random() for group in groups]
encrypt = [tc.encrypt(setup[i][0], message[i], ['1', '2', '3'] if i == 0 else '1 and 2 and 3') for i, tc in enumerate(testclasses)]

class BenchmarkTest1(unittest.TestCase):
    NUM_RUN = 50

    def benchmarkSetup(self):
        res = list()

        for _ in testclasses:
            res.append(list())

        for i in range(0, self.NUM_RUN):
            for j, tc in enumerate(testclasses):
                start_time = time.time()
                tc.setup()
                end_time = time.time()
                res[j].append(end_time - start_time)

        self.plot(res, "Setup", self.NUM_RUN)

    def benchmarkKeygen(self):
        res = list()
        keygens = list()
        keygens_length = list()
        for _ in testclasses:
            res.append(list())
            keygens_length.append(list())


        for i in range(0, self.NUM_RUN):
            current = list()
            for j, tc in enumerate(testclasses):
                S = [str(a) for a in range(1, i + 2)]
                if j == 0:
                    S = " and ".join(S)

                start_time = time.time()
                sk = tc.keygen(setup[j][0], setup[j][1], S)
                end_time = time.time()
                current.append(sk)
                keygens_length[j].append(sys.getsizeof(str(sk)))
                res[j].append(end_time - start_time)
            keygens.append(current)

        self.res_keygen = keygens
        self.plot(res, "Keygen", self.NUM_RUN)
        self.plot(keygens_length, "Keygen length", self.NUM_RUN)

    def benchmarkEncrypt(self):
        res = list()
        ciphertext_length = list()

        encrypts = list()
        for _ in testclasses:
            res.append(list())
            ciphertext_length.append(list())

        for i in range(0, self.NUM_RUN):
            current = list()
            for j, tc in enumerate(testclasses):
                S = [str(a) for a in range(1, i + 2)]
                if j != 0:
                    S = " and ".join(S)

                start_time = time.time()
                ct = tc.encrypt(setup[j][0], message[j], S)
                end_time = time.time()
                res[j].append(end_time - start_time)
                current.append(ct)
                ciphertext_length[j].append(sys.getsizeof(str(ct)))
            encrypts.append(current)


        self.res_encrypt = encrypts
        self.plot(res, "Encrypt", self.NUM_RUN)
        self.plot(ciphertext_length, "Ciphertext length", self.NUM_RUN)

    def benchmarkDecrypt(self):
        res = list()
        for _ in testclasses:
            res.append(list())

        for i in range(0, self.NUM_RUN):
            for j, tc in enumerate(testclasses):
                start_time = time.time()
                if j == 0:
                    tc.decrypt(self.res_encrypt[i][j], self.res_keygen[i][j])
                else:
                    tc.decrypt(setup[j][0], self.res_keygen[i][j], self.res_encrypt[i][j])
                end_time = time.time()
                res[j].append(end_time - start_time)

        self.plot(res, "Decrypt", self.NUM_RUN)

    def testall(self):
        self.benchmarkSetup()
        self.benchmarkKeygen()
        self.benchmarkEncrypt()
        self.benchmarkDecrypt()

    def plot(self, res, title, NUM_RUN):
        res = np.array(res)
        plt.title(title)
        plt.ylabel('time in s')
        plt.xlabel('# of attributes')
        plt.plot(np.linspace(1, NUM_RUN, num=NUM_RUN), res[0], label = "KP - [LSW 08]")
        plt.plot(np.linspace(1, NUM_RUN, num=NUM_RUN), res[1], label = "CP non-monoton - [YAHK 14]")
        plt.plot(np.linspace(1, NUM_RUN, num=NUM_RUN), res[2], label = "CP - [LW 14]")
        plt.legend()
        plt.show()
