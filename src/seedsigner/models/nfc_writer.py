import logging
import binascii
import time
from typing import Dict, Optional, Union
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
        """初期化"""
        self._nfc_module = None
        self._current_card_uid = None
        self._initialized = False

    def _initialize_nfc(self) -> bool:
        """NFC初期化（書き込み前に毎回実行）"""
        try:
            logger.info("Initializing NFC module...")
            
            # 現在のGPIOモードを確認
            try:
                import RPi.GPIO as GPIO
                current_mode = GPIO.getmode()
                logger.debug(f"Current GPIO mode: {current_mode}")
            except Exception:
                pass
            
            # NFCライブラリをインポート
            import board
            import busio
            from adafruit_pn532.i2c import PN532_I2C
            
            # I2C初期化
            i2c = busio.I2C(board.SCL, board.SDA)
            time.sleep(0.1)
            
            # PN532初期化
            self._nfc_module = PN532_I2C(i2c, debug=False, irq=None)
            time.sleep(0.1)
            
            # SAM設定
            self._nfc_module.SAM_configuration()
            
            self._initialized = True
            logger.info("NFC initialization successful")
            return True
            
        except Exception as e:
            logger.error(f"NFC initialization failed: {e}")
            self._nfc_module = None
            self._initialized = False
            return False

    def write_seed_to_nfc(self, seed: Seed) -> Dict[str, Union[bool, str, int]]:
        """シードをNFCカードに書き込む"""
        try:
            # 書き込み前にNFC初期化
            if not self._initialize_nfc():
                return {
                    'success': False,
                    'error_message': 'NFC module initialization failed. Check hardware connection.'
                }
            
            logger.info("Starting NFC write process...")
            
            # NFCカードの検出
            card_uid = self._wait_for_card()
            if not card_uid:
                return {
                    'success': False,
                    'error_message': 'NFC card not detected. Please place card on reader.'
                }
            
            # 空きセクタを検索
            empty_sector = self._find_empty_sector()
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
        """ブロックの認証を行う"""
        try:
            default_key = b'\xFF\xFF\xFF\xFF\xFF\xFF'
            
            if uid is None:
                uid = self._current_card_uid
            
            return self._nfc_module.mifare_classic_authenticate_block(
                uid, block_num, 0x60, default_key
            )
        except Exception as e:
            logger.debug(f"Authentication failed for block {block_num}: {e}")
            return False

    def _wait_for_card(self, timeout: int = 30) -> Optional[bytes]:
        """NFCカード検出待機"""
        logger.info("Waiting for NFC card...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                uid = self._nfc_module.read_passive_target(timeout=0.5)
                if uid is not None:
                    logger.info(f"NFC card detected: {[hex(i) for i in uid]}")
                    self._current_card_uid = uid
                    return uid
            except Exception:
                continue
            time.sleep(0.1)
        
        return None
    
    def _find_empty_sector(self) -> Optional[int]:
        """空きセクタ検索"""
        logger.info("Searching for empty sector...")
        
        for sector_num in range(1, self.MAX_SECTORS):  # セクタ0は除外
            try:
                management_block_num = sector_num * self.SECTOR_SIZE + 1
                
                if not self._authenticate_block(management_block_num):
                    continue
                
                management_block = self._nfc_module.mifare_classic_read_block(management_block_num)
                if management_block is None:
                    continue
                
                # 無効セクタかどうか確認
                if management_block[:4] != self.VALID_SECTOR_MARKER:
                    logger.info(f"Found empty sector: {sector_num}")
                    return sector_num
                
                time.sleep(0.1)
                
            except Exception:
                continue
        
        return None
    
    def _prepare_seed_data(self, seed: Seed) -> Dict[str, Union[bytes, int]]:
        """シードデータ準備"""
        mnemonic = seed.mnemonic_list
        wordlist = Seed.get_wordlist(SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
        
        if len(mnemonic) == 12:
            seed_type = self.SEED_128BIT
            words_to_encode = 11
        elif len(mnemonic) == 24:
            seed_type = self.SEED_256BIT
            words_to_encode = 23
        else:
            raise NFCWriteException(f"Unsupported seed length: {len(mnemonic)}")
        
        # 単語インデックス取得
        word_indices = []
        for i in range(words_to_encode):
            try:
                index = wordlist.index(mnemonic[i])
                word_indices.append(index)
            except ValueError:
                raise NFCWriteException(f"Word '{mnemonic[i]}' not found in wordlist")
        
        # 11ビット × 単語数でビット文字列作成
        bit_string = "".join(format(index, '011b') for index in word_indices)
        
        # バイト配列に変換
        compressed_seed = bytearray()
        for i in range(0, len(bit_string), 8):
            byte_str = bit_string[i:i+8].ljust(8, '0')
            compressed_seed.append(int(byte_str, 2))
        
        # チェックサム取得
        checksum_index = wordlist.index(mnemonic[-1])
        if checksum_index > 255:
            checksum_index = 255
        
        # フィンガープリント取得
        fingerprint_bytes = binascii.unhexlify(seed.get_fingerprint())
        
        logger.info(f"Seed type: {'128bit' if seed_type == self.SEED_128BIT else '256bit'}")
        logger.info(f"Compressed seed length: {len(compressed_seed)} bytes")
        
        return {
            'seed_type': seed_type,
            'checksum': checksum_index,
            'fingerprint': fingerprint_bytes,
            'compressed_seed': bytes(compressed_seed)
        }
    
    def _write_seed_to_sector(self, sector_num: int, seed_data: Dict) -> bool:
        """セクタにシードデータ書き込み"""
        try:
            compressed_seed = seed_data['compressed_seed']
            seed_type = seed_data['seed_type']
            
            # 1. シードブロック書き込み（2番目のブロック）
            block2_num = sector_num * self.SECTOR_SIZE + 2
            seed_block1 = bytearray(16)
            
            if compressed_seed:
                copy_length = min(16, len(compressed_seed))
                seed_block1[:copy_length] = compressed_seed[:copy_length]
            
            if not self._authenticate_block(block2_num):
                logger.error(f"Authentication failed for block {block2_num}")
                return False
            
            self._nfc_module.mifare_classic_write_block(block2_num, bytes(seed_block1))
            logger.info(f"Seed block 1 written to block {block2_num}")
            
            # 2. 256bitの場合は3番目のブロックも書き込み
            if seed_type == self.SEED_256BIT and len(compressed_seed) > 16:
                block3_num = sector_num * self.SECTOR_SIZE + 3
                
                if (block3_num % 4) == 3:  # トレーラーブロック衝突チェック
                    logger.error(f"Block {block3_num} conflicts with sector trailer")
                    return False
                
                seed_block2 = bytearray(16)
                remaining_data = compressed_seed[16:]
                
                if remaining_data:
                    copy_length = min(16, len(remaining_data))
                    seed_block2[:copy_length] = remaining_data[:copy_length]
                
                if not self._authenticate_block(block3_num):
                    logger.error(f"Authentication failed for block {block3_num}")
                    return False
                
                self._nfc_module.mifare_classic_write_block(block3_num, bytes(seed_block2))
                logger.info(f"Seed block 2 written to block {block3_num}")
            
            # 3. 管理ブロック書き込み（1番目のブロック）
            management_block_num = sector_num * self.SECTOR_SIZE + 1
            management_block = bytearray(16)
            
            # 管理データ設定
            management_block[0:4] = self.VALID_SECTOR_MARKER  # [0:3] 有効セクタマーカー
            management_block[4] = seed_data['seed_type']      # [4] シードタイプ
            management_block[7] = seed_data['checksum']       # [7] チェックサム
            
            # [8:15] フィンガープリント
            fingerprint_bytes = seed_data['fingerprint']
            if len(fingerprint_bytes) >= 8:
                management_block[8:16] = fingerprint_bytes[:8]
            else:
                management_block[8:8+len(fingerprint_bytes)] = fingerprint_bytes
            
            if not self._authenticate_block(management_block_num):
                logger.error(f"Authentication failed for management block")
                return False
            
            self._nfc_module.mifare_classic_write_block(management_block_num, bytes(management_block))
            logger.info(f"Management block written to block {management_block_num}")
            
            logger.info(f"Sector {sector_num} write completed successfully")
            return True
        
        except Exception as e:
            logger.error(f"Failed to write to sector {sector_num}: {e}")
            return False