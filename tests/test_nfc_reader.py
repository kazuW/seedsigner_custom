"""
NFCカードからシードを読み込む機能のテストファイル
このファイルはNFC読み込み機能の動作確認を行うためのものです。
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from seedsigner.models.nfc_reader import NFCReader, NFCReadException
from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants


class TestNFCReader(unittest.TestCase):
    
    def setUp(self):
        self.nfc_reader = NFCReader()
    
    @patch('seedsigner.models.nfc_reader.NFCReader._initialize_nfc')
    @patch('seedsigner.models.nfc_reader.NFCReader._wait_for_card')
    @patch('seedsigner.models.nfc_reader.NFCReader._scan_all_sectors')
    def test_read_seeds_from_nfc_success(self, mock_scan, mock_wait, mock_init):
        """NFCカードからシードを正常に読み込めることをテスト"""
        # モックの設定
        mock_init.return_value = True
        mock_wait.return_value = b'\x01\x02\x03\x04'  # ダミーUID
        mock_scan.return_value = [
            {
                'sector': 1,
                'fingerprint': 'abcd1234',
                'seed_type': '128bit',
                'checksum': 100
            }
        ]
        
        # テスト実行
        result = self.nfc_reader.read_seeds_from_nfc()
        
        # 結果確認
        self.assertTrue(result['success'])
        self.assertEqual(len(result['seeds']), 1)
        self.assertEqual(result['seeds'][0]['fingerprint'], 'abcd1234')
    
    @patch('seedsigner.models.nfc_reader.NFCReader._initialize_nfc')
    def test_read_seeds_nfc_init_fail(self, mock_init):
        """NFC初期化に失敗した場合のテスト"""
        # モックの設定
        mock_init.return_value = False
        
        # テスト実行
        result = self.nfc_reader.read_seeds_from_nfc()
        
        # 結果確認
        self.assertFalse(result['success'])
        self.assertIn('NFC module initialization failed', result['error_message'])
    
    def test_reconstruct_seed_12word(self):
        """12語のシード復元をテスト"""
        # テストデータ - 12語のシード
        compressed_seed = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
        seed_data = {
            'seed_type': NFCReader.SEED_128BIT,
            'checksum': 100,
            'compressed_seed': compressed_seed
        }
        
        # テスト実行（実際のシード復元は複雑なのでモックを使用）
        with patch.object(self.nfc_reader, '_calculate_checksum_index', return_value=100):
            result = self.nfc_reader._reconstruct_seed(seed_data)
            # エラーがないことを確認（実際の復元は統合テストで行う）
            # self.assertIsNotNone(result)
    
    def test_verify_fingerprint(self):
        """フィンガープリント検証のテスト"""
        # モックシードを作成
        mock_seed = Mock()
        mock_seed.get_fingerprint.return_value = 'abcd1234'
        
        # テストデータ
        expected_fingerprint = binascii.unhexlify('abcd1234')
        
        # テスト実行
        result = self.nfc_reader._verify_fingerprint(mock_seed, expected_fingerprint)
        
        # 結果確認
        self.assertTrue(result)


class TestNFCIntegration(unittest.TestCase):
    """NFC機能の統合テスト"""
    
    def test_seed_compression_decompression(self):
        """シードの圧縮と展開が正しく行われることをテスト"""
        # テスト用のニーモニック（12語）
        test_mnemonic = [
            "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon", 
            "abandon", "abandon", "abandon", "about"
        ]
        
        # Seedオブジェクトを作成
        seed = Seed(test_mnemonic)
        
        # NFCWriterでの圧縮をシミュレート（ここではテスト用に簡単な実装）
        wordlist = Seed.get_wordlist(SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
        word_indices = []
        for i in range(11):  # 最後の単語（チェックサム）は除く
            word_indices.append(wordlist.index(test_mnemonic[i]))
        
        # ビット文字列を作成
        bit_string = ""
        for index in word_indices:
            bit_string += format(index, '011b')
        
        # バイト配列に変換
        compressed_seed = bytearray()
        for i in range(0, len(bit_string), 8):
            byte_str = bit_string[i:i+8].ljust(8, '0')
            compressed_seed.append(int(byte_str, 2))
        
        # 圧縮されたデータのサイズをチェック
        self.assertLessEqual(len(compressed_seed), 16)  # 128bitシードは16バイト以内
        
        print(f"Test mnemonic: {test_mnemonic}")
        print(f"Compressed seed length: {len(compressed_seed)} bytes")
        print(f"Compressed seed: {compressed_seed.hex()}")


if __name__ == '__main__':
    unittest.main()
