import logging
import binascii
import struct
import time
import gc
from typing import Dict, List, Optional, Union
from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants

logger = logging.getLogger(__name__)

class NFCWriteException(Exception):
    """NFC書き込みエラーの例外クラス"""
    pass

class NFCWriter:
    """PN532モジュールを使用してNFCカードにシードを書き込むクラス"""
    
    # NFCカードの定数
    SECTOR_SIZE = 4
    BLOCK_SIZE = 16
    MAX_SECTORS = 16
    
    # 管理ブロックの定数
    VALID_SECTOR_MARKER = b'\xAA\x55\xFF\x00'
    SEED_128BIT = 0x00
    SEED_256BIT = 0xFF
    
    def __init__(self):
        """インスタンス変数として初期化"""
        self._nfc_module = None
        self._i2c_instance = None
        self._current_card_uid = None  # 現在のカードのUIDを保存
        self._initialize_nfc()
    
    def _initialize_nfc(self):
        """PN532モジュールを初期化（テストコードベース）"""
        try:
            # 既存インスタンスのクリーンアップ
            self._simple_cleanup()
            
            import board
            import busio
            from adafruit_pn532.i2c import PN532_I2C
            
            # テストコードと同じ初期化方法
            try:
                logger.info("Initializing I2C...")
                self._i2c_instance = busio.I2C(board.SCL, board.SDA)
                
                logger.info("Initializing PN532...")
                self._nfc_module = PN532_I2C(self._i2c_instance, debug=False, irq=None)
                
                logger.info("Configuring SAM...")
                self._nfc_module.SAM_configuration()
                
                logger.info("PN532 initialized successfully")
                return
                
            except Exception as e:
                logger.error(f"Simple initialization failed: {e}")
                raise NFCWriteException(f"NFC module initialization failed: {e}")
                
        except ImportError:
            logger.error("PN532 library not found")
            raise NFCWriteException("PN532 library not installed")
        except Exception as e:
            logger.error(f"Critical initialization failure: {e}")
            raise NFCWriteException(f"NFC module initialization failed: {e}")

    def _simple_cleanup(self):
        """シンプルなクリーンアップ"""
        try:
            if hasattr(self, '_nfc_module') and self._nfc_module is not None:
                del self._nfc_module
                self._nfc_module = None
            
            if hasattr(self, '_i2c_instance') and self._i2c_instance is not None:
                try:
                    self._i2c_instance.deinit()
                except:
                    pass
                del self._i2c_instance
                self._i2c_instance = None
            
            # 短い待機時間
            time.sleep(0.1)
            
            logger.info("Simple cleanup completed")
            
        except Exception as e:
            logger.warning(f"Simple cleanup failed: {e}")

    def _definitive_initialization(self):
        """確実な初期化方法"""
        from adafruit_pn532.i2c import PN532_I2C
        
        # PN532インスタンスを作成（resetなし）
        nfc_module = PN532_I2C(self._i2c_instance, debug=False)
        
        # 段階的な初期化
        try:
            # Step 1: 基本通信テスト
            firmware_version = nfc_module.firmware_version
            logger.info(f"PN532 firmware version: {firmware_version}")
            
            # Step 2: 慎重なSAM設定
            max_sam_attempts = 1  # 1回のみ試行
            for attempt in range(max_sam_attempts):
                try:
                    time.sleep(2.0)  # 十分な待機時間
                    nfc_module.SAM_configuration()
                    logger.info("SAM configuration successful")
                    return nfc_module
                except Exception as sam_error:
                    if "different mode" in str(sam_error).lower():
                        logger.warning("SAM already configured, proceeding...")
                        return nfc_module  # 既に設定済みなら継続
                    else:
                        raise sam_error
                        
        except Exception as e:
            logger.error(f"Definitive initialization failed: {e}")
            raise e

    def _create_test_mock(self):
        """テスト用モックモジュール"""
        class TestMockNFC:
            def read_passive_target(self, timeout=1):
                time.sleep(1)  # カード検出をシミュレート
                return b'\x04\x12\x34\x56'  # テスト用UID
            
            def mifare_classic_authenticate_block(self, block_num, key_type, key):
                return True
            
            def mifare_classic_read_block(self, block_num):
                # 空のブロックを返す
                return b'\x00' * 16
            
            def mifare_classic_write_block(self, block_num, data):
                logger.info(f"Mock write to block {block_num}: {binascii.hexlify(data).decode()}")
                return True
            
            def power_down(self):
                pass
            
            @property
            def firmware_version(self):
                return (1, 6, 7)
        
        logger.info("Created test mock NFC module")
        return TestMockNFC()

    def write_seed_to_nfc(self, seed: Seed) -> Dict[str, Union[bool, str, int]]:
        """シードをNFCカードに書き込む（改良版）"""
        try:
            logger.info("Starting NFC write process...")
            
            # NFCカードの検出を待つ
            card_uid = self._wait_for_card()
            if not card_uid:
                return {
                    'success': False,
                    'error_message': 'NFC card not detected. Please place card on reader.'
                }
            
            # カードの全セクタデータを読み込む
            sectors_data = self._read_all_sectors()
            
            # 空きセクタを検索
            empty_sector = self._find_empty_sector(sectors_data)
            if empty_sector is None:
                return {
                    'success': False,
                    'error_message': 'No empty sector available on NFC card.'
                }
            
            # シードデータを準備
            seed_data = self._prepare_seed_data(seed)
            
            # セクタに書き込み
            if self._write_seed_to_sector(empty_sector, seed_data):
                return {
                    'success': True,
                    'sector_num': empty_sector
                }
            else:
                return {
                    'success': False,
                    'error_message': 'Failed to write seed data to NFC card.'
                }
                
        except Exception as e:
            logger.error(f"NFC write error: {e}")
            return {
                'success': False,
                'error_message': str(e)
            }
    
    def _authenticate_block(self, block_num: int, uid: bytes = None) -> bool:
        """ブロックの認証を行う（テストコードベース）"""
        try:
            default_key = b'\xFF\xFF\xFF\xFF\xFF\xFF'
            
            # UIDが提供されていない場合は、現在のカードのUIDを使用
            if uid is None:
                uid = self._current_card_uid
            
            # テストコードと同じ認証方法
            return self._nfc_module.mifare_classic_authenticate_block(
                uid, block_num, 0x60, default_key
            )
        except Exception as e:
            logger.debug(f"Authentication failed for block {block_num}: {e}")
            return False

    def _wait_for_card(self, timeout: int = 30) -> Optional[bytes]:
        """NFCカードの検出を待つ（テストコードベース）"""
        logger.info("Waiting for NFC card...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                # テストコードと同じ検出方法
                uid = self._nfc_module.read_passive_target(timeout=0.5)
                if uid is not None:
                    logger.info(f"NFC card detected: {[hex(i) for i in uid]}")
                    self._current_card_uid = uid  # UIDを保存
                    return uid
            except Exception as e:
                logger.debug(f"Card detection attempt failed: {e}")
                continue
            
            time.sleep(0.1)
        
        return None
    
    def _read_all_sectors(self) -> Dict[int, List[bytes]]:
        """全セクタのデータを読み込む（テストコードベース）"""
        sectors_data = {}
        
        # テストコードと同じ範囲（0-63ブロック）
        for block_number in range(64):
            sector_number = block_number // 4
            block_index = block_number % 4
            
            # トレーラーブロックはスキップ
            if block_index == 3:
                continue
            
            # セクタ0はシステム領域なのでスキップ
            if sector_number == 0:
                continue
            
            try:
                # テストコードと同じ認証方法
                success = self._nfc_module.mifare_classic_authenticate_block(
                    self._current_card_uid, block_number, 0x60, b'\xFF\xFF\xFF\xFF\xFF\xFF'
                )
                
                if not success:
                    logger.warning(f"Authentication failed for block {block_number}")
                    continue
                
                # データ読み出し
                block_data = self._nfc_module.mifare_classic_read_block(block_number)
                if block_data is not None:
                    if sector_number not in sectors_data:
                        sectors_data[sector_number] = []
                    sectors_data[sector_number].append(block_data)
                    
                    logger.debug(f"Read block {block_number}: {' '.join('{:02X}'.format(x) for x in block_data)}")
                
                time.sleep(0.1)  # テストコードと同じ待機時間
                
            except Exception as e:
                logger.debug(f"Failed to read block {block_number}: {e}")
                continue
        
        return sectors_data
    
    def _find_empty_sector(self, sectors_data: Dict[int, List[bytes]]) -> Optional[int]:
        """空きセクタを検索する
        
        Args:
            sectors_data: セクタデータ
            
        Returns:
            int: 空きセクタ番号、見つからなければNone
        """
        for sector_num in range(1, self.MAX_SECTORS):
            if sector_num not in sectors_data:
                continue
            
            sector_blocks = sectors_data[sector_num]
            if len(sector_blocks) < 2:
                continue
            
            # 管理ブロック（2番目のブロック）をチェック
            management_block = sector_blocks[1]  # インデックス1が2番目のブロック
            
            # 有効セクタマーカーをチェック
            if management_block[:4] != self.VALID_SECTOR_MARKER:
                return sector_num  # 空きセクタが見つかった
        
        return None
    
    def _prepare_seed_data(self, seed: Seed) -> Dict[str, Union[bytes, int]]:
        """シードデータを準備する
        
        Args:
            seed: シードオブジェクト
            
        Returns:
            Dict: 準備されたシードデータ
        """
        mnemonic = seed.mnemonic_list
        wordlist = Seed.get_wordlist(SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
        
        # 単語数に応じてシードタイプを決定
        if len(mnemonic) == 12:
            seed_type = self.SEED_128BIT
            words_to_encode = 11  # チェックサムを除く
        elif len(mnemonic) == 24:
            seed_type = self.SEED_256BIT
            words_to_encode = 23  # チェックサムを除く
        else:
            raise NFCWriteException(f"Unsupported seed length: {len(mnemonic)}")
        
        # 各単語をインデックスに変換
        word_indices = []
        for i, word in enumerate(mnemonic):
            if i < words_to_encode:  # チェックサム単語以外
                try:
                    index = wordlist.index(word)
                    word_indices.append(index)
                except ValueError:
                    raise NFCWriteException(f"Word '{word}' not found in wordlist")
        
        # 11ビットずつエンコード
        bit_string = ""
        for index in word_indices:
            bit_string += format(index, '011b')
        
        # バイト配列に変換
        compressed_seed = bytearray()
        for i in range(0, len(bit_string), 8):
            byte_str = bit_string[i:i+8].ljust(8, '0')  # 8ビットに満たない場合は0埋め
            compressed_seed.append(int(byte_str, 2))
        
        # チェックサム（最後の単語）を取得
        checksum_word = mnemonic[-1]
        checksum_index = wordlist.index(checksum_word)
        
        # フィンガープリントを取得
        fingerprint = seed.get_fingerprint()
        fingerprint_bytes = binascii.unhexlify(fingerprint)
        
        return {
            'seed_type': seed_type,
            'checksum': checksum_index,
            'fingerprint': fingerprint_bytes,
            'compressed_seed': bytes(compressed_seed)
        }
    
    def _write_seed_to_sector(self, sector_num: int, seed_data: Dict) -> bool:
        """セクタにシードデータを書き込む
        
        Args:
            sector_num: セクタ番号
            seed_data: シードデータ
            
        Returns:
            bool: 書き込み成功/失敗
        """
        try:
            # 管理ブロックを作成
            management_block = bytearray(self.BLOCK_SIZE)
            management_block[0:4] = self.VALID_SECTOR_MARKER
            management_block[4] = seed_data['seed_type']
            management_block[7] = seed_data['checksum']
            management_block[8:16] = seed_data['fingerprint'][:8]  # 8バイトまで
            
            # シードデータブロックを作成
            seed_block = bytearray(self.BLOCK_SIZE)
            compressed_seed = seed_data['compressed_seed']
            seed_block[:len(compressed_seed)] = compressed_seed
            
            # ブロック書き込み
            management_block_num = sector_num * self.SECTOR_SIZE + 1  # 2番目のブロック
            seed_block_num = sector_num * self.SECTOR_SIZE + 2  # 3番目のブロック
            
            # 管理ブロックの認証と書き込み
            if not self._authenticate_block(management_block_num):
                logger.error(f"Authentication failed for management block {management_block_num}")
                return False
            
            self._nfc_module.mifare_classic_write_block(management_block_num, bytes(management_block))
            logger.info(f"Management block written to block {management_block_num}")
            
            # シードブロックの認証と書き込み
            if not self._authenticate_block(seed_block_num):
                logger.error(f"Authentication failed for seed block {seed_block_num}")
                return False
            
            self._nfc_module.mifare_classic_write_block(seed_block_num, bytes(seed_block))
            logger.info(f"Seed block written to block {seed_block_num}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to write to sector {sector_num}: {e}")
            return False