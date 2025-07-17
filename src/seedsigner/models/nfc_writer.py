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

# モジュールレベルのグローバル変数（起動時に1回だけ初期化）
_global_nfc_instance = None
_global_i2c_instance = None
_global_initialization_attempted = False
_global_initialization_successful = False

def _initialize_global_nfc():
    """グローバルNFCインスタンスを初期化（遅延実行）"""
    global _global_nfc_instance, _global_i2c_instance, _global_initialization_attempted, _global_initialization_successful
    
    if _global_initialization_attempted:
        return  # 既に初期化を試行済み
    
    _global_initialization_attempted = True
    
    try:
        # 遅延インポート（GPIO競合を回避）
        logger.info("Starting delayed import of NFC libraries...")
        
        # 現在のGPIOモードを確認
        try:
            import RPi.GPIO as GPIO
            current_mode = GPIO.getmode()
            logger.info(f"Current GPIO mode: {current_mode}")
            
            # BCMモードでない場合は警告
            if current_mode != GPIO.BCM:
                logger.warning(f"GPIO mode is {current_mode}, NFC requires BCM mode")
        except Exception as gpio_error:
            logger.warning(f"GPIO mode check failed: {gpio_error}")
        
        try:
            import board
            import busio
            from adafruit_pn532.i2c import PN532_I2C
            logger.info("NFC libraries imported successfully")
        except Exception as import_error:
            logger.error(f"Failed to import NFC libraries: {import_error}")
            raise import_error
        
        logger.info("Initializing global NFC instance...")
        
        # I2C初期化
        try:
            _global_i2c_instance = busio.I2C(board.SCL, board.SDA)
            time.sleep(0.1)
            logger.info("I2C initialization successful")
        except Exception as i2c_error:
            logger.error(f"I2C initialization failed: {i2c_error}")
            raise i2c_error
        
        # PN532初期化
        try:
            _global_nfc_instance = PN532_I2C(_global_i2c_instance, debug=False, irq=None)
            time.sleep(0.1)
            logger.info("PN532 instance creation successful")
        except Exception as pn532_error:
            logger.error(f"PN532 instance creation failed: {pn532_error}")
            raise pn532_error
        
        # SAM設定（改善版）
        try:
            # 既存の設定をリセットしてから設定
            logger.info("Attempting SAM configuration...")
            _global_nfc_instance.SAM_configuration()
            logger.info("SAM configuration successful")
            _global_initialization_successful = True
        except Exception as sam_error:
            logger.error(f"SAM configuration failed: {sam_error}")
            
            # 特定のエラーメッセージをチェック
            error_message = str(sam_error).lower()
            if "different mode" in error_message or "already been set" in error_message:
                logger.warning("SAM mode conflict detected, attempting recovery...")
                
                # リカバリを試行
                try:
                    # PN532を再作成
                    _global_nfc_instance = PN532_I2C(_global_i2c_instance, debug=False, irq=None)
                    time.sleep(0.3)  # より長い待機時間
                    
                    # フィームウェアバージョンを確認（チップが応答するかテスト）
                    fw_version = _global_nfc_instance.firmware_version
                    logger.info(f"PN532 firmware version: {fw_version}")
                    
                    # SAM設定を再試行
                    _global_nfc_instance.SAM_configuration()
                    logger.info("SAM configuration successful after recovery")
                    _global_initialization_successful = True
                    
                except Exception as recovery_error:
                    logger.error(f"Recovery failed: {recovery_error}")
                    # 完全に失敗
                    _global_initialization_successful = False
                    _global_nfc_instance = None
            else:
                # その他のエラーは失敗として扱う
                _global_initialization_successful = False
                _global_nfc_instance = None
                raise sam_error
        
        logger.info("Global NFC initialization completed successfully")
        
    except Exception as e:
        logger.error(f"Global NFC initialization failed: {e}")
        _global_initialization_successful = False
        _global_nfc_instance = None

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
        """初期化（遅延初期化）"""
        global _global_nfc_instance, _global_i2c_instance, _global_initialization_successful
        
        # 実際に使用されるときに初期化
        if not _global_initialization_attempted:
            _initialize_global_nfc()
        
        self._nfc_module = _global_nfc_instance
        self._i2c_instance = _global_i2c_instance
        self._current_card_uid = None
        self._initialized = _global_initialization_successful and (_global_nfc_instance is not None)
        
        logger.info(f"NFCWriter instance created, initialized: {self._initialized}")

    def write_seed_to_nfc(self, seed: Seed) -> Dict[str, Union[bool, str, int]]:
        """シードをNFCカードに書き込む（遅延初期化対応）"""
        try:
            # 初期化がまだの場合は再試行
            if not self._initialized:
                logger.info("Retrying NFC initialization...")
                _initialize_global_nfc()
                self._nfc_module = _global_nfc_instance
                self._initialized = _global_initialization_successful and (_global_nfc_instance is not None)
            
            if not self._initialized:
                return {
                    'success': False,
                    'error_message': 'NFC module not initialized properly. Please check hardware connection.'
                }
            
            if self._nfc_module is None:
                return {
                    'success': False,
                    'error_message': 'NFC module instance is None. Hardware may not be connected.'
                }
            
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
        """NFCカードの検出を待つ"""
        logger.info("Waiting for NFC card...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                uid = self._nfc_module.read_passive_target(timeout=0.5)
                if uid is not None:
                    logger.info(f"NFC card detected: {[hex(i) for i in uid]}")
                    self._current_card_uid = uid
                    return uid
            except Exception as e:
                logger.debug(f"Card detection attempt failed: {e}")
                continue
            
            time.sleep(0.1)
        
        return None
    
    def _read_all_sectors(self) -> Dict[int, List[bytes]]:
        """全セクタのデータを読み込む"""
        sectors_data = {}
        
        for block_number in range(64):
            sector_number = block_number // 4
            block_index = block_number % 4
            
            if block_index == 3:  # トレーラーブロック
                continue
            
            if sector_number == 0:  # システム領域
                continue
            
            try:
                success = self._nfc_module.mifare_classic_authenticate_block(
                    self._current_card_uid, block_number, 0x60, b'\xFF\xFF\xFF\xFF\xFF\xFF'
                )
                
                if not success:
                    logger.warning(f"Authentication failed for block {block_number}")
                    continue
                
                block_data = self._nfc_module.mifare_classic_read_block(block_number)
                if block_data is not None:
                    if sector_number not in sectors_data:
                        sectors_data[sector_number] = []
                    sectors_data[sector_number].append(block_data)
                    
                    logger.debug(f"Read block {block_number}: {' '.join('{:02X}'.format(x) for x in block_data)}")
                
                time.sleep(0.1)
                
            except Exception as e:
                logger.debug(f"Failed to read block {block_number}: {e}")
                continue
        
        return sectors_data
    
    def _find_empty_sector(self, sectors_data: Dict[int, List[bytes]]) -> Optional[int]:
        """空きセクタを検索する"""
        for sector_num in range(1, self.MAX_SECTORS):
            if sector_num not in sectors_data:
                continue
            
            sector_blocks = sectors_data[sector_num]
            if len(sector_blocks) < 2:
                continue
            
            management_block = sector_blocks[1]
            
            if management_block[:4] != self.VALID_SECTOR_MARKER:
                return sector_num
        
        return None
    
    def _prepare_seed_data(self, seed: Seed) -> Dict[str, Union[bytes, int]]:
        """シードデータを準備する"""
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
        
        word_indices = []
        for i, word in enumerate(mnemonic):
            if i < words_to_encode:
                try:
                    index = wordlist.index(word)
                    word_indices.append(index)
                except ValueError:
                    raise NFCWriteException(f"Word '{word}' not found in wordlist")
        
        bit_string = ""
        for index in word_indices:
            bit_string += format(index, '011b')
        
        compressed_seed = bytearray()
        for i in range(0, len(bit_string), 8):
            byte_str = bit_string[i:i+8].ljust(8, '0')
            compressed_seed.append(int(byte_str, 2))
        
        checksum_word = mnemonic[-1]
        checksum_index = wordlist.index(checksum_word)
        
        fingerprint = seed.get_fingerprint()
        fingerprint_bytes = binascii.unhexlify(fingerprint)
        
        return {
            'seed_type': seed_type,
            'checksum': checksum_index,
            'fingerprint': fingerprint_bytes,
            'compressed_seed': bytes(compressed_seed)
        }
    
    def _write_seed_to_sector(self, sector_num: int, seed_data: Dict) -> bool:
        """セクタにシードデータを書き込む"""
        try:
            management_block = bytearray(self.BLOCK_SIZE)
            management_block[0:4] = self.VALID_SECTOR_MARKER
            management_block[4] = seed_data['seed_type']
            management_block[7] = seed_data['checksum']
            management_block[8:16] = seed_data['fingerprint'][:8]
            
            seed_block = bytearray(self.BLOCK_SIZE)
            compressed_seed = seed_data['compressed_seed']
            seed_block[:len(compressed_seed)] = compressed_seed
            
            management_block_num = sector_num * self.SECTOR_SIZE + 1
            seed_block_num = sector_num * self.SECTOR_SIZE + 2
            
            if not self._authenticate_block(management_block_num):
                logger.error(f"Authentication failed for management block {management_block_num}")
                return False
            
            self._nfc_module.mifare_classic_write_block(management_block_num, bytes(management_block))
            logger.info(f"Management block written to block {management_block_num}")
            
            if not self._authenticate_block(seed_block_num):
                logger.error(f"Authentication failed for seed block {seed_block_num}")
                return False
            
            self._nfc_module.mifare_classic_write_block(seed_block_num, bytes(seed_block))
            logger.info(f"Seed block written to block {seed_block_num}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to write to sector {sector_num}: {e}")
            return False

# モジュールインポート時の初期化は行わない（遅延初期化）
# _initialize_global_nfc()  # <- この行を削除