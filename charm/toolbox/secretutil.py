'''
Contains all the auxillary functions to do linear secret sharing (LSS) over an access structure. Mainly, we represent the 
access structure as a binary tree. This could also support matrices for representing access structures.
'''
from charm.core.math.pairing import ZR
from charm.toolbox.policytree import *
import numpy as np
import re

class SecretUtil:
    def __init__(self, groupObj, verbose=True):
        self.group = groupObj        
#        self.parser = PolicyParser()

    def P(self, coeff, x):
        share = 0
        # evaluate polynomial
        for i in range(0, len(coeff)):
            share += (coeff[i] * (x ** i))
        return share

    def genShares(self, secret, k, n):
        if(k <= n):
            rand = self.group.random
            a = [] # will hold polynomial coefficients
            for i in range(0, k):
                if (i == 0): a.append(secret) # a[0]
                else: a.append(rand(ZR))
            Pfunc = self.P 
            shares = [Pfunc(a, i) for i in range(0, n+1)]
        return shares
    
    # shares is a dictionary
    def recoverCoefficients(self, list):
        """recovers the coefficients over a binary tree."""
        coeff = {}
        list2 = [self.group.init(ZR, i) for i in list]
        for i in list2:
            result = 1
            for j in list2:
                if not (i == j):
                    # lagrange basis poly
                    result *= (0 - j) / (i - j)
#                print("coeff '%d' => '%s'" % (i, result))
            coeff[int(i)] = result
        return coeff
        
    def recoverSecret(self, shares):
        """take shares and attempt to recover secret by taking sum of coeff * share for all shares.
        if user indeed has at least k of n shares, then secret will be recovered."""
        list = shares.keys()
        if self.verbose: print(list)
        coeff = self.recoverCoefficients(list)
        secret = 0
        for i in list:
            secret += (coeff[i] * shares[i])

        return secret

    def getCoefficients(self, tree):
        coeffs = {}
        self._getCoefficientsDict(tree, coeffs)
        return coeffs
    
    def _getCoefficientsDict(self, tree, coeff_list, coeff=1):
        """recover coefficient over a binary tree where possible node types are OR = (1 of 2)
        and AND = (2 of 2) secret sharing. The leaf nodes are attributes and the coefficients are
        recorded in a coeff-list dictionary.""" 
        if tree:
            node = tree.getNodeType()
            if(node == OpType.AND):
                this_coeff = self.recoverCoefficients([1,2])
                # left child => coeff[1], right child => coeff[2]
                self._getCoefficientsDict(tree.getLeft(), coeff_list, coeff * this_coeff[1])
                self._getCoefficientsDict(tree.getRight(), coeff_list, coeff * this_coeff[2])
            elif(node == OpType.OR):
                this_coeff = self.recoverCoefficients([1])
                self._getCoefficientsDict(tree.getLeft(), coeff_list, coeff * this_coeff[1])
                self._getCoefficientsDict(tree.getRight(), coeff_list, coeff * this_coeff[1])
            elif(node == OpType.ATTR):
                attr = tree.getAttributeAndIndex()
                coeff_list[ attr ] = coeff
            else:
                return None
            
    def _calculateShares(self, secret, tree, _type=dict):
        """performs secret sharing over a policy tree. could be adapted for LSSS matrices."""
        attr_list = []
        self._compute_shares(secret, tree, attr_list)
        if _type == list:
            return attr_list
        else: # assume dict
            share = {}
            for i in range(0, len(attr_list)):
                key = attr_list[i][0].getAttributeAndIndex()
                if not key in share.keys():
                    share[ key ] = attr_list[i][1]
            return share
    
    def calculateSharesList(self, secret, tree):
        """calculate shares from given secret and returns a list of shares."""        
        return self._calculateShares(secret, tree, list)
    
    def calculateSharesDict(self, secret, tree):
        """calculate shares from given secret and returns a dict as {attribute:shares} pairs"""        
        return self._calculateShares(secret, tree, dict)

    def _get_num_ANDs(self, root, subtree, c = 0):
        queue = list()
        queue.append(root)
        # level order traversal
        while len(queue) > 0:
            node = queue.pop(0)
            if node.getNodeType() == OpType.AND:
                c += 1
            if node is subtree:
                return c
            if node.getLeft().getNodeType() != OpType.ATTR:
                queue.append(node.getLeft())
            if node.getRight().getNodeType() != OpType.ATTR:
                queue.append(node.getRight())

    def calculateLSSSMatrix(self, root):
        """
        Calculates the LSSS matrix of the given parsed policy tree.
        Currently does only support threshold gates of 1-of-n (OR) or n-of-n (AND)

        :param root: the root node of the tree
        :return: the LSSS matrix as an numpy array, the list p mapping each row of A to an attribute
        """
        matrix, p = self._calculateLSSSMatrix(root, root, [1], 0, [], [])
        # print(matrix)
        # print(p)
        max_elem = -1
        for elem in matrix:
            max_elem = max(max_elem, len(elem))
        for elem in matrix:
            elem += [0] * (max_elem - len(elem))
        return np.array(matrix), p

    def _calculateLSSSMatrix(self, root, subtree, vector, c, matrix, p):
        if subtree is None:
            return None, None
        op_type = subtree.getNodeType()
        if op_type == OpType.ATTR:
            matrix.append(vector)
            p.append(subtree.getAttribute())
        elif op_type == OpType.AND:
            c = self._get_num_ANDs(root, subtree)
            vector_left = [0] * c
            vector_left.append(-1)
            self._calculateLSSSMatrix(root, subtree.getLeft(), vector_left, c, matrix, p)
            if len(vector) < c:
                vector += [0] * (c-len(vector))
            vector.append(1)
            self._calculateLSSSMatrix(root, subtree.getRight(), vector.copy(), c, matrix, p)
        elif op_type == OpType.OR:
            self._calculateLSSSMatrix(root, subtree.getLeft(), vector.copy(), c, matrix, p)
            self._calculateLSSSMatrix(root, subtree.getRight(), vector.copy(), c, matrix, p)
        else:
            print("unsupported OpType: " + op_type)
        return matrix, p

    def findMatchingLSSSRows(self, matrix, p, attributes):
        """
        For each row of the matrix it is checked if the given attribute list can satisfy this row.
        If so it is appended in the result set.
        The mapping of the original rows to the subset rows are saved in the second return paramter.
        :param matrix: the original LSSS matrix
        :param matrix: the p mapping of each row of A to an attribute
        :param attributes: the attributes of the user
        :return: the subset rows of the matrix, the mapping of original row of the matrix to the index of the attribute list
        """
        attributes = list(attributes)
        policy_A = np.array([matrix[k] for k in range(0, len(p)) if p[k] in attributes])
        attr_index = np.array([(k, attributes.index(p[k])) for k in range(0, len(p)) if p[k] in attributes])
        return policy_A, attr_index

    def _find_linear_independent_rows(self, matrix):
        ks = list()
        independent_rows = list()
        for k, row in enumerate(matrix):
            for i in independent_rows:
                if np.array_equal(row, i):
                    break
            else:
                ks.append(k)
                independent_rows.append(row)
        return np.array(ks), np.array(independent_rows)

    def solveLSSSMatrix(self, A):
        num_rows = A.shape[0]
        num_cols = A.shape[1]
        if num_rows < num_cols:
            raise Exception("Not enough arguments to satisfy policy. (%d/%d)." % A.shape)
        # print(A)
        expected_solution = np.zeros(A.shape[1])
        expected_solution[0] = 1
        if num_rows > num_cols:
            # make square
            k, A = self._find_linear_independent_rows(A)
            k = k[:num_cols]
            A = A[:num_cols,:]
        else:
            k = range(0, num_cols)

        return k, np.linalg.solve(A.T, expected_solution).astype(int)

    def _compute_shares(self, secret, subtree, List):
        """computes recursive secret sharing over the binary tree. Start by splitting 1-of-2 (OR) or 2-of-2 (AND nodes).
         Continues recursively down the tree doing a round of secret sharing at each boolean node type."""
        k = 0
        if(subtree == None):
            return None
        
        type = subtree.getNodeType()
        if(type == OpType.ATTR):
            # visiting a leaf node
#            t = (subtree.getAttribute(), secret)
            t = (subtree, secret)
            List.append(t)
            return None
        elif(type == OpType.OR or type == OpType.AND):
            k = subtree.threshold # 1-of-2 or 2-of-2
#        elif(type == OpType.AND):
#            k = 2 # 2-of-2
        else:
            return None
        # generate shares for k and n        
        shares = self.genShares(secret, k, n=2)
        # recursively generate shares for children nodes
        self._compute_shares(shares[1], subtree.getLeft(), List)
        self._compute_shares(shares[2], subtree.getRight(), List)
    
    def strip_index(self, node_str):
        if node_str.find('_') != -1: return node_str.split('_')[0]
        return node_str
        
    
    def createPolicy(self, policy_string):
        assert type(policy_string) == str, "invalid type for policy_string"
        parser = PolicyParser()        
        policy_obj = parser.parse(policy_string)
        _dictCount, _dictLabel = {}, {}
        parser.findDuplicates(policy_obj, _dictCount)
        for i in _dictCount.keys(): 
            if _dictCount[ i ] > 1: _dictLabel[ i ] = 0
        parser.labelDuplicates(policy_obj, _dictLabel)
        return policy_obj
        
    def prune(self, policy, attributes):
        """determine whether a given set of attributes satisfies the policy"""
        parser = PolicyParser()        
        return parser.prune(policy, attributes)
    
    def getAttributeList(self, Node):
        aList = []
        self._getAttributeList(Node, aList)
        return aList
            
    def _getAttributeList(self, Node, List):
        """retrieve the attributes that occur in a policy tree in order (left to right)"""
        if(Node == None):
            return None
        # V, L, R
        if(Node.getNodeType() == OpType.ATTR):
            List.append(Node.getAttributeAndIndex()) # .getAttribute()
        else:
            self._getAttributeList(Node.getLeft(), List)
            self._getAttributeList(Node.getRight(), List)
        return None

    def to_dnf_matrix(self, policy_str):
        # [()\s]+ matches any ( or ) and any whitspace character
        dist = re.split(r"[()\s]+or[()\s]+", policy_str, flags=re.IGNORECASE)
        ret = list()
        for i, d in enumerate(dist):
            ret.append(re.split(r"[()\s]+and[()\s]+", d, flags=re.IGNORECASE))
        return ret

    def createNofNThresholdPolicy(self, policy_str):
        any_brackets_or_whitespaces = "[()\s]+"
        and_with_sperators = re.compile(any_brackets_or_whitespaces + "and" + any_brackets_or_whitespaces, flags=re.IGNORECASE)
        or_with_sperators = re.compile(any_brackets_or_whitespaces + "or" + any_brackets_or_whitespaces, flags=re.IGNORECASE)

        # matches any ( or ) or whitespace befor and after an 'and' and removes it
        values = re.split(and_with_sperators, policy_str)
        for value in values:
            assert not or_with_sperators.match(value), "Only n-of-n threshold policy supported (only AND support)."
        return values



# TODO: add test cases here for SecretUtil
if __name__ == "__main__":
    pass

