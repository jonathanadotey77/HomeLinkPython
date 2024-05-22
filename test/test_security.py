from homelink_python.security import *

from unittest import TestCase

class TestSecurity(TestCase):
    
    def testRandomBytes(self):
        arr = [randomBytes(32) for _ in range(10)]
        for i in range(len(arr)):
            for j in range(len(arr)):
                if i != j:
                    self.assertNotEqual(arr[i], arr[j])
    
    def testGenerateRSAKeys(self):
        key = generateRSAKeys()

        self.assertEqual(key.size_in_bits(), RSA_KEY_SIZE)
        self.assertTrue(key.can_encrypt())
        self.assertTrue(key.has_private())
        self.assertTrue(key.can_sign())