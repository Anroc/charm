import unittest, sys
import time

from charm.schemes.abenc.abenc_lsw08 import KPabe
from charm.schemes.abenc.abenc_unmcpabe_yahk14 import CPABE_YAHK14
from charm.schemes.abenc.abenc_lw14 import CPabe_LW14
from charm.toolbox.pairinggroup import PairingGroup, GT

import matplotlib.pyplot as plt
import numpy as np


class BenchmarkTest1(unittest.TestCase):
    groups = [PairingGroup('MNT224'),  PairingGroup('SS512'),  PairingGroup('SS512')]
    testclasses = [KPabe(groups[0]), CPABE_YAHK14(groups[1]), CPabe_LW14(groups[2])]
    # TODO: fix me
    # setup = [tc.setup() for tc in testclasses]
    # keygen = [tc.keygen(setup[i][0], setup[i][1], ['1', '2', '3'] if i != 0 else '1 and 2 and 3') for i, tc in enumerate(testclasses)]
    # message = [group.random() for group in groups]
    # encrypt = [tc.keygen(setup[i][0], message[i], ['1', '2', '3'] if i == 0 else '1 and 2 and 3') for i, tc in enumerate(testclasses)]

    def testBenchmarkSetup(self):
        res = list()
        NUM_RUN = 100

        for _ in self.testclasses:
            res.append(list())

        for i in range(0, NUM_RUN):
            for j, tc in enumerate(self.testclasses):
                start_time = time.time()
                tc.setup()
                end_time = time.time()
                res[j].append(end_time - start_time)

        self.plot(res, NUM_RUN)


    def testBenchmarkKeygen(self):
        res = list()
        NUM_RUN = 100

        for _ in self.testclasses:
            res.append(list())

        for i in range(0, NUM_RUN):
            for j, tc in enumerate(self.testclasses):
                if j != 0:
                    S = ['1', '2', '3']
                else:
                    S = '1 and 2 and 3'

                start_time = time.time()
                tc.keygen(self.setup[i][0], self.setup[i][1], S)
                end_time = time.time()
                res[j].append(end_time - start_time)

        self.plot(res, NUM_RUN)

    def testBenchmarkEncrypt(self):
        res = list()
        NUM_RUN = 100

        for _ in self.testclasses:
            res.append(list())

        for i in range(0, NUM_RUN):
            for j, tc in enumerate(self.testclasses):
                if j == 0:
                    S = ['1', '2', '3']
                else:
                    S = '1 and 2 and 3'
                pp, mk = tc.setup()
                sk = tc.keygen(pp, mk, S)

                start_time = time.time()
                tc.encrypt(pp, mk, S)
                end_time = time.time()
                res[j].append(end_time - start_time)

        self.plot(res, NUM_RUN)

    def plot(self, res, NUM_RUN):
        res = np.array(res)
        plt.ylabel('time in s')
        plt.xlabel('# run')
        plt.plot(np.linspace(1, NUM_RUN, num=NUM_RUN), res[0], label = "KP")
        plt.plot(np.linspace(1, NUM_RUN, num=NUM_RUN), res[1], label = "CP non-monoton")
        plt.plot(np.linspace(1, NUM_RUN, num=NUM_RUN), res[2], label = "CP")
        plt.axhline(y = np.average(res[0]), color = 'b')
        plt.axhline(y = np.average(res[1]), color = 'b')
        plt.axhline(y = np.average(res[2]), color = 'b')
        plt.legend()
        plt.show()
