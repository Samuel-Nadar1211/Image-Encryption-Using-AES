import unittest
from cryptobox.aes import g, keyExpansion, addRoundKey, subBytes, shiftRows, mixColumns, cipher, decipher, invSubBytes, invShiftRows, inv_mix_columns
import random

class TestAESFunctions(unittest.TestCase):

    def setUp(self):
        self.plaintext = [1, 35, 69, 103, 137, 171, 205, 239, 254, 220, 186, 152, 118, 84, 50, 16]
        self.ciphertext_128 = [255, 11, 132, 74, 8, 83, 191, 124, 105, 52, 171, 67, 100, 20, 143, 185]
        self.ciphertext_192 = [183, 32, 87, 148, 150, 145, 56, 183, 89, 44, 136, 200, 73, 140, 181, 248]
        self.ciphertext_256 = [179, 170, 156, 241, 129, 85, 139, 194, 142, 11, 75, 76, 173, 97, 148, 177]

        self.key_128 = [15, 21, 113, 201, 71, 217, 232, 89, 12, 183, 173, 214, 175, 127, 103, 152]
        self.key_192 = [157, 155, 229, 194, 23, 2, 238, 109, 241, 109, 225, 160, 39, 193, 29, 2, 172, 76, 127, 242, 162, 146, 75, 162]
        self.key_256 = [234, 111, 213, 181, 57, 77, 218, 248, 118, 164, 204, 221, 32, 36, 11, 103, 90, 152, 36, 30, 151, 97, 122, 11, 179, 126, 4, 47, 49, 119, 0, 4]

        self.expanded_key_128 = [[15, 21, 113, 201], [71, 217, 232, 89], [12, 183, 173, 214], [175, 127, 103, 152], [220, 144, 55, 176], [155, 73, 223, 233], [151, 254, 114, 63], [56, 129, 21, 167], [210, 201, 107, 183], [73, 128, 180, 94], [222, 126, 198, 97], [230, 255, 211, 198], [192, 175, 223, 57], [137, 47, 107, 103], [87, 81, 173, 6], [177, 174, 126, 192], [44, 92, 101, 241], [165, 115, 14, 150], [242, 34, 163, 144], [67, 140, 221, 80], [88, 157, 54, 235], [253, 238, 56, 125], [15, 204, 155, 237], [76, 64, 70, 189], [113, 199, 76, 194], [140, 41, 116, 191], [131, 229, 239, 82], [207, 165, 169, 239], [55, 20, 147, 72], [187, 61, 231, 247], [56, 216, 8, 165], [247, 125, 161, 74], [72, 38, 69, 32], [243, 27, 162, 215], [203, 195, 170, 114], [60, 190, 11, 56], [253, 13, 66, 203], [14, 22, 224, 28], [197, 213, 74, 110], [249, 107, 65, 86], [180, 142, 243, 82], [186, 152, 19, 78], [127, 77, 89, 32], [134, 38, 24, 118]]
        self.expanded_key_192 = [[157, 155, 229, 194], [23, 2, 238, 109], [241, 109, 225, 160], [39, 193, 29, 2], [172, 76, 127, 242], [162, 146, 75, 162], [211, 40, 223, 248], [196, 42, 49, 149], [53, 71, 208, 53], [18, 134, 205, 55], [190, 202, 178, 197], [28, 88, 249, 103], [187, 177, 90, 100], [127, 155, 107, 241], [74, 220, 187, 196], [88, 90, 118, 243], [230, 144, 196, 54], [250, 200, 61, 81], [87, 150, 139, 73], [40, 13, 224, 184], [98, 209, 91, 124], [58, 139, 45, 143], [220, 27, 233, 185], [38, 211, 212, 232], [57, 222, 16, 190], [17, 211, 240, 6], [115, 2, 171, 122], [73, 137, 134, 245], [149, 146, 111, 76], [179, 65, 187, 164], [170, 52, 89, 211], [187, 231, 169, 213], [200, 229, 2, 175], [129, 108, 132, 90], [20, 254, 235, 22], [167, 191, 80, 178], [130, 103, 110, 143], [57, 128, 199, 90], [241, 101, 197, 245], [112, 9, 65, 175], [100, 247, 170, 185], [195, 72, 250, 11], [144, 74, 69, 161], [169, 202, 130, 251], [88, 175, 71, 14], [40, 166, 6, 161], [76, 81, 172, 24], [143, 25, 86, 19], [196, 251, 56, 210], [109, 49, 186, 41], [53, 158, 253, 39], [29, 56, 251, 134]]
        self.expanded_key_256 = [[234, 111, 213, 181], [57, 77, 218, 248], [118, 164, 204, 221], [32, 36, 11, 103], [90, 152, 36, 30], [151, 97, 122, 11], [179, 126, 4, 47], [49, 119, 0, 4], [30, 12, 39, 114], [39, 65, 253, 138], [81, 229, 49, 87], [113, 193, 58, 48], [249, 224, 164, 26], [110, 129, 222, 17], [221, 255, 218, 62], [236, 136, 218, 58], [216, 91, 167, 188], [255, 26, 90, 54], [174, 255, 107, 97], [223, 62, 81, 81], [103, 82, 117, 203], [9, 211, 171, 218], [212, 44, 113, 228], [56, 164, 171, 222], [149, 57, 186, 187], [106, 35, 224, 141], [196, 220, 139, 236], [27, 226, 218, 189], [200, 202, 34, 177], [193, 25, 137, 107], [21, 53, 248, 143], [45, 145, 83, 81], [28, 212, 107, 99], [118, 247, 139, 238], [178, 43, 0, 2], [169, 201, 218, 191], [27, 23, 117, 185], [218, 14, 252, 210], [207, 59, 4, 93], [226, 170, 87, 12], [160, 143, 149, 251], [214, 120, 30, 21], [100, 83, 30, 23], [205, 154, 196, 168], [166, 175, 105, 123], [124, 161, 149, 169], [179, 154, 145, 244], [81, 48, 198, 248], [132, 59, 212, 42], [82, 67, 202, 63], [54, 16, 212, 40], [251, 138, 16, 128], [169, 209, 163, 182], [213, 112, 54, 31], [102, 234, 167, 235], [55, 218, 97, 19], [147, 212, 169, 176], [193, 151, 99, 143], [247, 135, 183, 167], [12, 13, 167, 39]]

    def test_g(self):
        w = [0xe6, 0xff, 0xd3, 0xc6]
        expected = [0x12, 0x66, 0xb4, 0x8e]
        g(w, 3)
        self.assertEqual(w, expected)

    def test_key128Expansion(self):
        expanded_key = keyExpansion(self.key_128)
        self.assertEqual(expanded_key, self.expanded_key_128)
    
    def test_key192Expansion(self):
        expanded_key = keyExpansion(self.key_192)
        self.assertEqual(expanded_key, self.expanded_key_192)
    
    def test_key256Expansion(self):
        expanded_key = keyExpansion(self.key_256)
        self.assertEqual(expanded_key, self.expanded_key_256)

    def test_addRoundKey(self):
        state = [[0xb1, 0xc1, 0x0b, 0xcc],
                 [0xba, 0xf3, 0x8b, 0x07],
                 [0xf9, 0x1f, 0x6a, 0xc3],
                 [0x1d, 0x19, 0x24, 0x5c]]
        round = 3
        addRoundKey(state, round, self.expanded_key_128)
        expected = [[0x71, 0x48, 0x5c, 0x7d],
                    [0x15, 0xdc, 0xda, 0xa9],
                    [0x26, 0x74, 0xc7, 0xbd],
                    [0x24, 0x7e, 0x22, 0x9c]]
        self.assertEqual(state, expected)

    def test_subBytes(self):
        state =  [[0x71, 0x48, 0x5c, 0x7d],
                  [0x15, 0xdc, 0xda, 0xa9],
                  [0x26, 0x74, 0xc7, 0xbd],
                  [0x24, 0x7e, 0x22, 0x9c]]
        subBytes(state)
        expected = [[0xa3, 0x52, 0x4a, 0xff],
                    [0x59, 0x86, 0x57, 0xd3],
                    [0xf7, 0x92, 0xc6, 0x7a],
                    [0x36, 0xf3, 0x93, 0xde]]
        self.assertEqual(state, expected)

    def test_invSubBytes(self):
        state =  [[0xa3, 0x52, 0x4a, 0xff],
                    [0x59, 0x86, 0x57, 0xd3],
                    [0xf7, 0x92, 0xc6, 0x7a],
                    [0x36, 0xf3, 0x93, 0xde]]
        invSubBytes(state)
        expected = [[0x71, 0x48, 0x5c, 0x7d],
                   [0x15, 0xdc, 0xda, 0xa9],
                   [0x26, 0x74, 0xc7, 0xbd],
                   [0x24, 0x7e, 0x22, 0x9c]]
        self.assertEqual(state, expected)

    def test_shiftRows(self):
        state =   [[0xa3, 0x52, 0x4a, 0xff],
                   [0x59, 0x86, 0x57, 0xd3],
                   [0xf7, 0x92, 0xc6, 0x7a],
                   [0x36, 0xf3, 0x93, 0xde]]
        shiftRows(state)
        expected = [[0xa3, 0x52, 0x4a, 0xff],
                    [0x86, 0x57, 0xd3, 0x59],
                    [0xc6, 0x7a, 0xf7, 0x92],
                    [0xde, 0x36, 0xf3, 0x93]]
        self.assertEqual(state, expected)

    def test_invShiftRows(self):
        state = [[0xa3, 0x52, 0x4a, 0xff],
                    [0x86, 0x57, 0xd3, 0x59],
                    [0xc6, 0x7a, 0xf7, 0x92],
                    [0xde, 0x36, 0xf3, 0x93]]
        invShiftRows(state)
        expected =   [[0xa3, 0x52, 0x4a, 0xff],
                   [0x59, 0x86, 0x57, 0xd3],
                   [0xf7, 0x92, 0xc6, 0x7a],
                   [0x36, 0xf3, 0x93, 0xde]]
        
        self.assertEqual(state, expected)

    def test_mixColumns(self):
        state =  [[0xa3, 0x52, 0x4a, 0xff],
                    [0x86, 0x57, 0xd3, 0x59],
                    [0xc6, 0x7a, 0xf7, 0x92],
                    [0xde, 0x36, 0xf3, 0x93]]
        mixColumns(state)
        expected = [[0xd4, 0x11, 0xfe, 0x0f],
                    [0x3b, 0x44, 0x06, 0x73],
                    [0xcb, 0xab, 0x62, 0x37],
                    [0x19, 0xb7, 0x07, 0xec]]
        self.assertEqual(state, expected)

    def test_inv_mix_columns(self):
        state =  [[0xd4, 0x11, 0xfe, 0x0f],
                    [0x3b, 0x44, 0x06, 0x73],
                    [0xcb, 0xab, 0x62, 0x37],
                    [0x19, 0xb7, 0x07, 0xec]]
        inv_mix_columns(state)
        expected = [[0xa3, 0x52, 0x4a, 0xff],
                    [0x86, 0x57, 0xd3, 0x59],
                    [0xc6, 0x7a, 0xf7, 0x92],
                    [0xde, 0x36, 0xf3, 0x93]]
        self.assertEqual(state, expected)

    def test_cipher128(self):
        ciphertext = cipher(self.plaintext, self.key_128)
        self.assertEqual(ciphertext, self.ciphertext_128)

    def test_decipher128(self):
        plaintext = decipher(self.ciphertext_128, self.key_128)
        self.assertEqual(plaintext, self.plaintext)

    def test_cipher192(self):
        ciphertext = cipher(self.plaintext, self.key_192)
        self.assertEqual(ciphertext, self.ciphertext_192)

    def test_decipher192(self):
        plaintext = decipher(self.ciphertext_192, self.key_192)
        self.assertEqual(plaintext, self.plaintext)

    def test_cipher256(self):
        ciphertext = cipher(self.plaintext, self.key_256)
        self.assertEqual(ciphertext, self.ciphertext_256)

    def test_decipher256(self):
        plaintext = decipher(self.ciphertext_256, self.key_256)
        self.assertEqual(plaintext, self.plaintext)

    
    def test_random_cases(self):
        for _ in range(10):
            # Random 128-bit key and plaintext
            key = [random.randint(0, 255) for _ in range(16)]
            plaintext = [random.randint(0, 255) for _ in range(16)]
            # Encrypt and then decrypt
            ciphertext = cipher(plaintext, key)
            decrypted_text = decipher(ciphertext, key)
            assert decrypted_text == plaintext, f"Random test failed: {decrypted_text} != {plaintext}"

        for _ in range(10):
            # Random 192-bit key and 128-bit plaintext
            key = [random.randint(0, 255) for _ in range(24)]
            plaintext = [random.randint(0, 255) for _ in range(16)]
            # Encrypt and then decrypt
            ciphertext = cipher(plaintext, key)
            decrypted_text = decipher(ciphertext, key)
            assert decrypted_text == plaintext, f"Random test failed: {decrypted_text} != {plaintext}"

        for _ in range(10):
            # Random 256-bit key and 128-bit plaintext
            key = [random.randint(0, 255) for _ in range(32)]
            plaintext = [random.randint(0, 255) for _ in range(16)]
            # Encrypt and then decrypt
            ciphertext = cipher(plaintext, key)
            decrypted_text = decipher(ciphertext, key)
            assert decrypted_text == plaintext, f"Random test failed: {decrypted_text} != {plaintext}"


if __name__ == '__main__':
    unittest.main()
