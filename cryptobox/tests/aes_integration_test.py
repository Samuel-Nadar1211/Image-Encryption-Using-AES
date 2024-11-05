import unittest, random
from cryptobox.aes import cipher, decipher, keyExpansion, subBytes, s_box, ROUNDS


class TestAESIntegration(unittest.TestCase):

    def setUp(self):
        # Test vectors
        self.plaintext = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]
        self.key = [0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59,
               0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98]
        self.expected_ciphertext = [0xff, 0x0b, 0x84, 0x4a, 0x08, 0x53, 0xbf, 0x7c,
                               0x69, 0x34, 0xab, 0x43, 0x64, 0x14, 0x8f, 0xb9]


    def test_encryption_decryption(self):
        # Perform encryption
        encrypted_text = cipher(self.plaintext, self.key)
        # Perform decryption
        decrypted_text = decipher(encrypted_text, self.key)
        # Check if decrypted text matches the original plaintext
        self.assertEqual(decrypted_text, self.plaintext, "Decrypted text does not match the original plaintext")
    

    def test_random_cases(self):
        for _ in range(10):
            # Random 128-bit key and plaintext
            key = [random.randint(0, 255) for _ in range(16)]
            plaintext = [random.randint(0, 255) for _ in range(16)]
            # Encrypt and then decrypt
            ciphertext = cipher(plaintext, key)
            decrypted_text = decipher(ciphertext, key)
            assert decrypted_text == plaintext, f"Random test failed: {decrypted_text} != {plaintext}"

        print("Random AES Tests Passed")

if __name__ == '__main__':
    unittest.main()