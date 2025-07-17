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
    
    # クラス変数でインスタンスを管理
    _instance = None
    _nfc_module = None
    _i2c_instance = None
    
    def __new__(cls):
        """シングルトンパターンでインスタンスを管理"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._nfc_module is None:
            self._initialize_nfc()
    
    def _initialize_nfc(self):
        """PN532モジュールを初期化（初期化問題の改善版）"""
        try:
            # 既存のインスタンスをクリア
            self._cleanup_existing_instances()
            
            import board
            import busio
            from adafruit_pn532.i2c import PN532_I2C
            
            # I2C接続の初期化
            try:
                # 既存のI2Cインスタンスがあれば完全に削除
                if self._i2c_instance is not None:
                    try:
                        self._i2c_instance.deinit()
                    except:
                        pass
                    del self._i2c_instance
                    self._i2c_instance = None
                    time.sleep(0.3)
                
                # I2Cインスタンスを作成
                self._i2c_instance = busio.I2C(board.SCL, board.SDA, frequency=100000)
                logger.info("I2C interface initialized")
                
            except Exception as i2c_error:
                logger.error(f"I2C initialization failed: {i2c_error}")
                raise NFCWriteException(f"I2C initialization failed: {i2c_error}")
            
            # PN532の初期化を複数の方法で試行
            initialization_methods = [
                ("Hardware Reset", self._try_hardware_reset),
                ("Software Reset", self._try_software_reset),
                ("Basic Initialization", self._try_basic_initialization),
                ("Force Initialization", self._try_force_initialization)
            ]
            
            for method_name, method_func in initialization_methods:
                try:
                    logger.info(f"Attempting {method_name}...")
                    self._nfc_module = method_func()
                    if self._nfc_module is not None:
                        logger.info(f"PN532 initialized successfully with {method_name}")
                        return
                except Exception as e:
                    logger.warning(f"{method_name} failed: {e}")
                    # 失敗時は部分的なクリーンアップを実行
                    self._partial_cleanup()
                    continue
            
            raise NFCWriteException("All initialization methods failed")
            
        except ImportError:
            logger.error("PN532 library not found. Please install adafruit-circuitpython-pn532")
            raise NFCWriteException("PN532 library not installed")
        except Exception as e:
            logger.error(f"Failed to initialize PN532: {e}")
            raise NFCWriteException(f"NFC module initialization failed: {e}")
    
    def _cleanup_existing_instances(self):
        """既存のインスタンスを完全にクリーンアップ"""
        try:
            if self._nfc_module is not None:
                try:
                    # NFCモジュールを適切に終了
                    self._nfc_module.power_down()
                    time.sleep(0.1)
                except:
                    pass
                
                del self._nfc_module
                self._nfc_module = None
                logger.info("Existing NFC module instance cleaned up")
            
            if self._i2c_instance is not None:
                try:
                    self._i2c_instance.deinit()
                    time.sleep(0.1)
                except:
                    pass
                
                del self._i2c_instance
                self._i2c_instance = None
                logger.info("Existing I2C instance cleaned up")
            
            # ガベージコレクションを強制実行
            gc.collect()
            time.sleep(0.5)  # 長めの待機時間
            
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")
    
    def _partial_cleanup(self):
        """部分的なクリーンアップ（失敗時の処理）"""
        try:
            if self._nfc_module is not None:
                try:
                    self._nfc_module.power_down()
                except:
                    pass
                del self._nfc_module
                self._nfc_module = None
            
            time.sleep(0.2)
            
        except Exception as e:
            logger.warning(f"Partial cleanup failed: {e}")
    
    def _try_hardware_reset(self):
        """ハードウェアリセットを試行"""
        from adafruit_pn532.i2c import PN532_I2C
        
        # resetピンを使用してハードウェアリセット
        nfc_module = PN532_I2C(self._i2c_instance, debug=False, reset=True)
        
        # 明示的なハードウェアリセット
        nfc_module.reset()
        time.sleep(1.0)  # 長い待機時間
        
        # SAM設定
        nfc_module.SAM_configuration()
        
        return nfc_module
    
    def _try_software_reset(self):
        """ソフトウェアリセットを試行"""
        from adafruit_pn532.i2c import PN532_I2C
        
        nfc_module = PN532_I2C(self._i2c_instance, debug=False)
        
        # ソフトウェアリセットを複数回試行
        for attempt in range(5):
            try:
                nfc_module.reset()
                time.sleep(0.5)
                
                # 電源管理でリセット
                nfc_module.power_down()
                time.sleep(0.3)
                nfc_module.wake_up()
                time.sleep(0.3)
                
                # SAM設定
                nfc_module.SAM_configuration()
                
                return nfc_module
                
            except Exception as e:
                logger.warning(f"Software reset attempt {attempt + 1} failed: {e}")
                if attempt < 4:
                    time.sleep(0.5 * (attempt + 1))
                else:
                    raise e
    
    def _try_basic_initialization(self):
        """基本的な初期化を試行"""
        from adafruit_pn532.i2c import PN532_I2C
        
        nfc_module = PN532_I2C(self._i2c_instance, debug=False)
        
        # SAM設定を段階的に実行
        for attempt in range(10):
            try:
                time.sleep(0.2 * (attempt + 1))
                nfc_module.SAM_configuration()
                return nfc_module
                
            except Exception as e:
                if attempt == 9:
                    raise e
                logger.warning(f"Basic initialization attempt {attempt + 1} failed: {e}")
                continue
    
    def _try_force_initialization(self):
        """強制初期化を試行"""
        import board
        import busio
        from adafruit_pn532.i2c import PN532_I2C
        
        # I2Cインスタンスを完全に再作成
        try:
            self._i2c_instance.deinit()
            time.sleep(0.5)
        except:
            pass
        
        # 低速でI2Cを再初期化
        self._i2c_instance = busio.I2C(board.SCL, board.SDA, frequency=50000)
        time.sleep(0.5)
        
        # PN532を初期化
        nfc_module = PN532_I2C(self._i2c_instance, debug=False)
        
        # 段階的な設定
        time.sleep(1.0)
        nfc_module.SAM_configuration()
        
        return nfc_module
    
    def write_seed_to_nfc(self, seed: Seed) -> Dict[str, Union[bool, str, int]]:
        """シードをNFCカードに書き込む
        
        Args:
            seed: 書き込むシードオブジェクト
            
        Returns:
            Dict: 書き込み結果
        """
        try:
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
    
    def _wait_for_card(self, timeout: int = 30) -> Optional[bytes]:
        """NFCカードの検出を待つ
        
        Args:
            timeout: タイムアウト時間（秒）
            
        Returns:
            bytes: カードUID、検出できなければNone
        """
        logger.info("Waiting for NFC card...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                uid = self._nfc_module.read_passive_target(timeout=1)
                if uid:
                    logger.info(f"NFC card detected: {binascii.hexlify(uid).decode()}")
                    return uid
            except Exception as e:
                logger.debug(f"Card detection attempt failed: {e}")
                continue
            
            time.sleep(0.1)
        
        return None
    
    def _read_all_sectors(self) -> Dict[int, List[bytes]]:
        """全セクタのデータを読み込む
        
        Returns:
            Dict: セクタ番号をキーとする各セクタのブロックデータ
        """
        sectors_data = {}
        
        for sector in range(1, self.MAX_SECTORS):  # セクタ0はシステム用なので除外
            try:
                sector_data = []
                for block in range(self.SECTOR_SIZE):
                    block_num = sector * self.SECTOR_SIZE + block
                    
                    # トレーラーブロックは読み込まない
                    if block == 3:  # トレーラーブロック
                        continue
                    
                    # 認証してブロックを読み込む
                    if self._authenticate_block(block_num):
                        block_data = self._nfc_module.mifare_classic_read_block(block_num)
                        sector_data.append(block_data)
                        # ログ出力
                        logger.debug(f"Read block {block_num}: {binascii.hexlify(block_data).decode()}")
                        # 読み込み間隔を空ける
                        time.sleep(0.1)
                    else:
                        logger.warning(f"Authentication failed for block {block_num}")
                        break
                
                if len(sector_data) == 3:  # 3ブロック正常に読み込めた場合
                    sectors_data[sector] = sector_data
                    
            except Exception as e:
                logger.debug(f"Failed to read sector {sector}: {e}")
                continue
        
        return sectors_data
    
    def _authenticate_block(self, block_num: int) -> bool:
        """ブロックの認証を行う
        
        Args:
            block_num: ブロック番号
            
        Returns:
            bool: 認証成功/失敗
        """
        try:
            # デフォルトキーで認証を試行
            default_key = b'\xFF\xFF\xFF\xFF\xFF\xFF'
            return self._nfc_module.mifare_classic_authenticate_block(
                block_num, 0x60, default_key  # 0x60 = Key A
            )
        except Exception as e:
            logger.debug(f"Authentication failed for block {block_num}: {e}")
            return False
    
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