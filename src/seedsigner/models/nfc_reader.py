import logging
import binascii
import time
from typing import Dict, List, Optional, Union, Tuple
from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants

logger = logging.getLogger(__name__)

class NFCReadException(Exception):
    """NFC読み込みエラーの例外クラス"""
    pass

class NFCReader:
    """PN532モジュールを使用してNFCカードからシードを読み込むクラス"""
    
    # NFCカードの定数 - NFCWriterと同じ定数を使用
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
        """NFC初期化（読み込み前に毎回実行）"""
        try:
            logger.info("Initializing NFC module for reading...")
            
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
            logger.info("NFC initialization for reading successful")
            return True
            
        except Exception as e:
            logger.error(f"NFC initialization failed: {e}")
            self._nfc_module = None
            self._initialized = False
            return False
    
    def read_seeds_from_nfc(self) -> Dict[str, Union[bool, str, List[Dict]]]:
        """NFCカードから全ての有効なシードを読み込む"""
        try:
            # 読み込み前にNFC初期化
            if not self._initialize_nfc():
                return {
                    'success': False,
                    'error_message': 'NFC module initialization failed. Check hardware connection.'
                }
            
            logger.info("Starting NFC read process...")
            
            # NFCカードの検出
            card_uid = self._wait_for_card()
            if not card_uid:
                return {
                    'success': False,
                    'error_message': 'NFC card not detected. Please place card on reader.'
                }
            
            # 全セクタをスキャンして有効なシードを検索
            valid_seeds = self._scan_all_sectors()
            
            if not valid_seeds:
                return {
                    'success': True,
                    'seeds': [],
                    'message': 'No valid seeds found on NFC card.'
                }
            
            logger.info(f"Found {len(valid_seeds)} valid seeds on NFC card")
            return {
                'success': True,
                'seeds': valid_seeds
            }
                
        except Exception as e:
            logger.error(f"NFC read error: {e}")
            return {
                'success': False,
                'error_message': str(e)
            }
    
    def load_seed_from_nfc(self, sector_num: int, passphrase: str = "") -> Dict[str, Union[bool, str, Seed]]:
        """指定されたセクタからシードをロードする"""
        try:
            # 読み込み前にNFC初期化
            if not self._initialize_nfc():
                return {
                    'success': False,
                    'error_message': 'NFC module initialization failed. Check hardware connection.'
                }
            
            # NFCカードの検出
            card_uid = self._wait_for_card()
            if not card_uid:
                return {
                    'success': False,
                    'error_message': 'NFC card not detected. Please place card on reader.'
                }
            
            # 指定されたセクタからシードを読み込む
            seed_data = self._read_seed_from_sector(sector_num)
            if not seed_data:
                return {
                    'success': False,
                    'error_message': f'Failed to read seed from sector {sector_num}.'
                }
            
            # シードを復元
            seed = self._reconstruct_seed(seed_data, passphrase)
            if not seed:
                return {
                    'success': False,
                    'error_message': 'Failed to reconstruct seed from NFC data.'
                }
            
            # フィンガープリントを検証
            if not self._verify_fingerprint(seed, seed_data['fingerprint']):
                return {
                    'success': False,
                    'error_message': 'Fingerprint verification failed. Invalid passphrase or corrupted data.'
                }
            
            return {
                'success': True,
                'seed': seed
            }
                
        except Exception as e:
            logger.error(f"NFC seed load error: {e}")
            return {
                'success': False,
                'error_message': str(e)
            }
    
    def delete_seed_from_nfc(self, sector_num: int) -> Dict[str, Union[bool, str]]:
        """指定されたセクタからシードを削除する"""
        try:
            # 削除前にNFC初期化
            if not self._initialize_nfc():
                return {
                    'success': False,
                    'error_message': 'NFC module initialization failed. Check hardware connection.'
                }
            
            # NFCカードの検出
            card_uid = self._wait_for_card()
            if not card_uid:
                return {
                    'success': False,
                    'error_message': 'NFC card not detected. Please place card on reader.'
                }
            
            # セクタのブロックを削除（0x00で埋める）
            if self._clear_sector(sector_num):
                return {
                    'success': True,
                    'message': f'Seed deleted from sector {sector_num}.'
                }
            else:
                return {
                    'success': False,
                    'error_message': f'Failed to delete seed from sector {sector_num}.'
                }
                
        except Exception as e:
            logger.error(f"NFC seed delete error: {e}")
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
            
            # 認証を試行（Key Aで試行）
            auth_result = self._nfc_module.mifare_classic_authenticate_block(
                uid, block_num, 0x60, default_key
            )
            
            if not auth_result:
                # Key Aで失敗した場合、Key Bで試行
                logger.debug(f"Key A authentication failed for block {block_num}, trying Key B")
                auth_result = self._nfc_module.mifare_classic_authenticate_block(
                    uid, block_num, 0x61, default_key
                )
            
            if auth_result:
                logger.debug(f"Authentication successful for block {block_num}")
            else:
                logger.debug(f"Authentication failed for block {block_num} with both keys")
            
            return auth_result
            
        except Exception as e:
            logger.debug(f"Authentication exception for block {block_num}: {e}")
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
    
    def _scan_all_sectors(self) -> List[Dict]:
        """全セクタをスキャンして有効なシードを検索"""
        logger.info("Starting sector scan for valid seeds...")
        valid_seeds = []
        scanned_sectors = 0
        consecutive_auth_failures = 0
        
        for sector_num in range(1, self.MAX_SECTORS):  # セクタ0は除外
            try:
                scanned_sectors += 1
                logger.debug(f"Scanning sector {sector_num} ({scanned_sectors}/{self.MAX_SECTORS-1})")
                
                management_block_num = sector_num * self.SECTOR_SIZE  # セクタの最初のブロック（4,8,12,...）
                
                if not self._authenticate_block(management_block_num):
                    logger.debug(f"Authentication failed for management block {management_block_num} in sector {sector_num}")
                    consecutive_auth_failures += 1
                    
                    # 連続で認証失敗が3回以上の場合、カードの再検出を試行
                    if consecutive_auth_failures >= 3:
                        logger.warning(f"Multiple authentication failures detected, attempting card reconnection...")
                        time.sleep(0.2)
                        # カードの再検出を試行
                        uid = self._wait_for_card(timeout=2)
                        if uid:
                            self._current_card_uid = uid
                            consecutive_auth_failures = 0
                            logger.info("Card reconnected successfully")
                        else:
                            logger.warning("Card reconnection failed")
                    
                    # 認証失敗時は短時間待機してから次のセクタへ
                    time.sleep(0.05)
                    continue
                
                # 認証成功時はカウンタリセット
                consecutive_auth_failures = 0
                
                management_block = self._nfc_module.mifare_classic_read_block(management_block_num)
                if management_block is None:
                    logger.debug(f"Failed to read management block {management_block_num} in sector {sector_num}")
                    continue
                
                logger.debug(f"Management block data: {binascii.hexlify(management_block).decode('utf-8')}")
                
                # 有効セクタかどうか確認
                if management_block[:4] == self.VALID_SECTOR_MARKER:
                    logger.info(f"Valid seed marker found in sector {sector_num}")
                    
                    seed_type = management_block[4]
                    # 16-bitチェックサムを読み込み（bytes [5:6]から）
                    checksum_high = management_block[5]
                    checksum_low = management_block[6]
                    checksum = (checksum_high << 8) | checksum_low
                    fingerprint = management_block[8:16]
                    
                    logger.debug(f"Seed type: {seed_type} ({'128bit' if seed_type == self.SEED_128BIT else '256bit'})")
                    logger.debug(f"16-bit checksum: {checksum} (0x{checksum:04X}) from bytes [{checksum_high}, {checksum_low}]")
                    logger.debug(f"Fingerprint bytes: {binascii.hexlify(fingerprint).decode('utf-8')}")
                    
                    # シードブロック1を読み込み（sector*4+1）
                    block2_num = sector_num * self.SECTOR_SIZE + 1
                    logger.debug(f"Reading seed block 1 (block {block2_num})")
                    
                    if not self._authenticate_block(block2_num):
                        logger.warning(f"Authentication failed for seed block 1 (block {block2_num}) in sector {sector_num}")
                        # 認証失敗時は短時間待機してから次のセクタへ
                        time.sleep(0.05)
                        continue
                    
                    seed_block1 = self._nfc_module.mifare_classic_read_block(block2_num)
                    if seed_block1 is None:
                        logger.warning(f"Failed to read seed block 1 (block {block2_num}) in sector {sector_num}")
                        continue
                    
                    logger.debug(f"Seed block 1 data: {binascii.hexlify(seed_block1).decode('utf-8')}")
                    compressed_seed = bytearray(seed_block1)
                    
                    # 256bitの場合はシードブロック2も読み込み（sector*4+2）
                    if seed_type == self.SEED_256BIT:
                        block3_num = sector_num * self.SECTOR_SIZE + 2
                        logger.debug(f"Reading seed block 2 (block {block3_num}) for 256bit seed")
                        
                        if not self._authenticate_block(block3_num):
                            logger.warning(f"Authentication failed for seed block 2 (block {block3_num}) in sector {sector_num}")
                            # 認証失敗時は短時間待機してから次のセクタへ
                            time.sleep(0.05)
                            continue
                        
                        seed_block2 = self._nfc_module.mifare_classic_read_block(block3_num)
                        if seed_block2 is None:
                            logger.warning(f"Failed to read seed block 2 (block {block3_num}) in sector {sector_num}")
                            continue
                        
                        logger.debug(f"Seed block 2 data: {binascii.hexlify(seed_block2).decode('utf-8')}")
                        compressed_seed.extend(seed_block2)
                    
                    logger.debug(f"Complete compressed seed data ({len(compressed_seed)} bytes): {binascii.hexlify(compressed_seed).decode('utf-8')}")
                    
                    # シードからニーモニックを復元
                    logger.debug(f"Attempting to decompress seed data to mnemonic...")
                    mnemonic = self._decompress_seed_to_mnemonic(compressed_seed, seed_type, checksum)
                    if not mnemonic:
                        logger.warning(f"Failed to decompress seed in sector {sector_num}")
                        continue
                    
                    logger.debug(f"Successfully decompressed to {len(mnemonic)}-word mnemonic")
                    logger.debug(f"Mnemonic preview: {mnemonic[0]}...{mnemonic[-1]} (first and last words)")
                    
                    # フィンガープリントを16進文字列に変換
                    fingerprint_hex = binascii.hexlify(fingerprint).decode('utf-8')
                    
                    seed_info = {
                        'sector': sector_num,
                        'fingerprint': fingerprint_hex,
                        'seed_type': '128bit' if seed_type == self.SEED_128BIT else '256bit',
                        'checksum': checksum,
                        'mnemonic': mnemonic
                    }
                    
                    valid_seeds.append(seed_info)
                    
                    logger.info(f"✓ Valid seed found in sector {sector_num}: fingerprint={fingerprint_hex}, type={seed_info['seed_type']}, words={len(mnemonic)}")
                
                else:
                    logger.debug(f"No valid seed marker in sector {sector_num} (marker: {binascii.hexlify(management_block[:4]).decode('utf-8')})")
                
                time.sleep(0.1)
                
            except Exception as e:
                logger.warning(f"Error reading sector {sector_num}: {e}")
                continue
        
        logger.info(f"Sector scan completed: {len(valid_seeds)} valid seeds found out of {scanned_sectors} sectors scanned")
        
        if valid_seeds:
            logger.info("Summary of found seeds:")
            for i, seed in enumerate(valid_seeds, 1):
                logger.info(f"  {i}. Sector {seed['sector']}: {seed['fingerprint'][:8]}... ({seed['seed_type']})")
        else:
            logger.info("No valid seeds found on NFC card")
        
        return valid_seeds
    
    def _read_seed_from_sector(self, sector_num: int) -> Optional[Dict]:
        """指定されたセクタからシードデータを読み込む"""
        try:
            # 管理ブロック読み込み（セクタの最初のブロック: sector*4）
            management_block_num = sector_num * self.SECTOR_SIZE  # セクタの最初のブロック（4,8,12,...）
            
            if not self._authenticate_block(management_block_num):
                logger.error(f"Authentication failed for management block")
                return None
            
            management_block = self._nfc_module.mifare_classic_read_block(management_block_num)
            if management_block is None or management_block[:4] != self.VALID_SECTOR_MARKER:
                logger.error(f"Invalid sector {sector_num}")
                return None
            
            seed_type = management_block[4]
            # 16-bitチェックサムを読み込み（bytes [5:6]から）
            checksum_high = management_block[5]
            checksum_low = management_block[6]
            checksum = (checksum_high << 8) | checksum_low
            fingerprint = management_block[8:16]
            
            # シードブロック1読み込み（sector*4+1）
            block2_num = sector_num * self.SECTOR_SIZE + 1
            if not self._authenticate_block(block2_num):
                logger.error(f"Authentication failed for seed block 1")
                return None
            
            seed_block1 = self._nfc_module.mifare_classic_read_block(block2_num)
            if seed_block1 is None:
                logger.error(f"Failed to read seed block 1")
                return None
            
            compressed_seed = bytearray(seed_block1)
            
            # 256bitの場合はシードブロック2も読み込み（sector*4+2）
            if seed_type == self.SEED_256BIT:
                block3_num = sector_num * self.SECTOR_SIZE + 2
                
                if not self._authenticate_block(block3_num):
                    logger.error(f"Authentication failed for seed block 2")
                    return None
                
                seed_block2 = self._nfc_module.mifare_classic_read_block(block3_num)
                if seed_block2 is None:
                    logger.error(f"Failed to read seed block 2")
                    return None
                
                compressed_seed.extend(seed_block2)
            
            return {
                'seed_type': seed_type,
                'checksum': checksum,
                'fingerprint': fingerprint,
                'compressed_seed': bytes(compressed_seed)
            }
            
        except Exception as e:
            logger.error(f"Error reading seed from sector {sector_num}: {e}")
            return None
    
    def _reconstruct_seed(self, seed_data: Dict, passphrase: str = "") -> Optional[Seed]:
        """圧縮されたシードデータからSeedオブジェクトを復元"""
        try:
            seed_type = seed_data['seed_type']
            checksum = seed_data['checksum']
            compressed_seed = seed_data['compressed_seed']
            
            # 128bitか256bitかを判定
            if seed_type == self.SEED_128BIT:
                num_words = 12
                words_to_decode = 11
            elif seed_type == self.SEED_256BIT:
                num_words = 24
                words_to_decode = 23
            else:
                logger.error(f"Invalid seed type: {seed_type}")
                return None
            
            # 圧縮されたシードをビット文字列に変換
            bit_string = ""
            for byte in compressed_seed:
                bit_string += format(byte, '08b')
            
            # 11ビットずつ区切って単語インデックスを復元
            word_indices = []
            for i in range(words_to_decode):
                start_bit = i * 11
                end_bit = start_bit + 11
                if end_bit <= len(bit_string):
                    word_index = int(bit_string[start_bit:end_bit], 2)
                    word_indices.append(word_index)
            
            # BIP39ワードリストから単語を取得
            wordlist = Seed.get_wordlist(SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
            mnemonic = []
            
            for index in word_indices:
                if index >= len(wordlist):
                    logger.error(f"Invalid word index: {index}")
                    return None
                mnemonic.append(wordlist[index])
            
            # チェックサム単語を追加
            if checksum >= len(wordlist):
                logger.error(f"Invalid checksum index: {checksum} (must be 0-{len(wordlist)-1} for BIP39)")
                return None
            mnemonic.append(wordlist[checksum])
            
            # BIP39標準のチェックサム検証を実行
            # 11個の単語からBIP39仕様に従ってチェックサムを計算し、12番目の単語と一致するか確認
            logger.info(f"NFCReader: Starting BIP39 checksum validation for reconstructed seed")
            logger.debug(f"NFCReader: Partial mnemonic ({len(mnemonic)} words): {' '.join(mnemonic)}")
            logger.debug(f"NFCReader: Stored checksum: {checksum} -> '{wordlist[checksum]}'")
            
            calculated_checksum_index = self._calculate_checksum_index(mnemonic[:-1], num_words)
            if calculated_checksum_index != checksum:
                logger.error(f"NFCReader: ✗ BIP39 checksum verification FAILED:")
                logger.error(f"NFCReader:   Calculated using embit.bip39: {calculated_checksum_index}")
                logger.error(f"NFCReader:   Stored in NFC:               {checksum}")
                logger.error(f"NFCReader: This means the stored seed is not a valid BIP39 mnemonic")
                return None
            
            logger.info(f"NFCReader: ✓ BIP39 checksum verification SUCCESSFUL:")
            logger.info(f"NFCReader:   Calculated: {calculated_checksum_index} == Stored: {checksum}")
            logger.info(f"NFCReader: ✓ NFC Reader uses same checksum calculation as CompactSeedQR processing")
            logger.info(f"NFCReader: === Final Verification ===")
            logger.info(f"NFCReader: If this matches CompactSeedQR logs, both methods are identical")
            
            # Seedオブジェクトを作成
            seed = Seed(mnemonic, passphrase)
            
            logger.info(f"Successfully reconstructed {num_words}-word seed")
            return seed
            
        except Exception as e:
            logger.error(f"Error reconstructing seed: {e}")
            return None
    
    def _decompress_seed_to_mnemonic(self, compressed_seed: bytes, seed_type: int, checksum: int) -> Optional[List[str]]:
        """圧縮されたシードデータからニーモニックを復元（パスフレーズなし）"""
        try:
            # 128bitか256bitかを判定
            if seed_type == self.SEED_128BIT:
                num_words = 12
                expected_bytes = 16  # 128ビット = 16バイト
            elif seed_type == self.SEED_256BIT:
                num_words = 24
                expected_bytes = 32  # 256ビット = 32バイト
            else:
                logger.error(f"Invalid seed type: {seed_type}")
                return None
            
            logger.debug(f"Compressed seed hex: {binascii.hexlify(compressed_seed).decode('utf-8')}")
            logger.debug(f"Compressed seed length: {len(compressed_seed)} bytes (expected: {expected_bytes})")
            
            # SeedQRと同じ方法でembitライブラリを使用してニーモニックを復元
            try:
                from embit import bip39
                logger.info(f"NFCReader: Using embit.bip39.mnemonic_from_bytes (same as QR code)")
                logger.debug(f"NFCReader: Input entropy: {binascii.hexlify(compressed_seed).decode('utf-8')}")
                
                # 圧縮されたシードバイトから直接ニーモニックを生成
                mnemonic_string = bip39.mnemonic_from_bytes(compressed_seed)
                mnemonic = mnemonic_string.split()
                
                logger.info(f"NFCReader: Generated {len(mnemonic)}-word mnemonic using embit.bip39.mnemonic_from_bytes")
                logger.debug(f"NFCReader: Complete mnemonic: {' '.join(mnemonic)}")
                logger.debug(f"NFCReader: First word: '{mnemonic[0]}', Last word: '{mnemonic[-1]}'")
                
                if len(mnemonic) != num_words:
                    logger.error(f"NFCReader: Generated mnemonic has {len(mnemonic)} words, expected {num_words}")
                    return None
                
                # 最後の単語（チェックサム単語）のインデックスを取得
                wordlist = Seed.get_wordlist(SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
                generated_checksum_word = mnemonic[-1]
                generated_checksum_index = wordlist.index(generated_checksum_word)
                
                logger.info(f"NFCReader: Generated checksum word: '{generated_checksum_word}' -> index {generated_checksum_index}")
                logger.info(f"NFCReader: Stored checksum index: {checksum} -> word '{wordlist[checksum]}'")
                
                # CompactSeedQRとの比較情報をログ出力
                logger.info(f"NFCReader: === CompactSeedQR Comparison ===")
                logger.info(f"NFCReader: This entropy should match CompactSeedQR entropy: {binascii.hexlify(compressed_seed).decode('utf-8')}")
                logger.info(f"NFCReader: This mnemonic should match CompactSeedQR: {' '.join(mnemonic)}")
                logger.info(f"NFCReader: This checksum should match CompactSeedQR: '{generated_checksum_word}' (index {generated_checksum_index})")
                
                # チェックサム検証の詳細ログ
                if generated_checksum_index == checksum:
                    logger.info(f"NFCReader: ✓ Checksum verification successful: {generated_checksum_index} == {checksum}")
                    logger.info(f"NFCReader: ✓ Both NFC and CompactSeedQR use identical embit.bip39 methods")
                    logger.info(f"NFCReader: ✓ Expected: CompactSeedQR and NFC should produce identical results")
                    logger.info(f"NFCReader: ✓ Both NFC and QR code methods produce identical results")
                    return mnemonic
                else:
                    logger.error(f"NFCReader: ✗ Checksum verification failed:")
                    logger.error(f"NFCReader:   Generated by embit.bip39: {generated_checksum_index} -> '{generated_checksum_word}'")
                    logger.error(f"NFCReader:   Stored in NFC:            {checksum} -> '{wordlist[checksum]}'")
                    logger.error(f"NFCReader: This indicates a mismatch between NFC storage and QR code generation")
                    return None
                    
            except Exception as e:
                logger.error(f"Error using embit.bip39.mnemonic_from_bytes: {e}")
                return None
            
        except Exception as e:
            logger.error(f"Error decompressing seed to mnemonic: {e}")
            return None
    
    def _calculate_checksum_index(self, partial_mnemonic: List[str], total_words: int) -> int:
        """部分的なニーモニックからチェックサムインデックスを計算（QRコードと同じembit.bip39を使用）"""
        try:
            logger.info(f"NFCReader: Calculating BIP39 checksum for {len(partial_mnemonic)} words (expecting {total_words} total)")
            logger.debug(f"NFCReader: Input words: {partial_mnemonic}")
            
            # QRコードと同じ方法でembit.bip39を直接使用
            from embit import bip39
            
            # 11語または23語からバイト列に変換
            try:
                # 部分的なニーモニックを結合してバイト列に変換
                partial_mnemonic_string = " ".join(partial_mnemonic)
                logger.debug(f"NFCReader: Partial mnemonic string: '{partial_mnemonic_string}'")
                
                # embitのbip39を使用してエントロピーを取得
                entropy = bip39.mnemonic_to_bytes(partial_mnemonic_string, ignore_checksum=True)
                logger.info(f"NFCReader: Entropy from partial mnemonic: {binascii.hexlify(entropy).decode('utf-8')}")
                
                # エントロピーから完全なニーモニックを生成（チェックサム付き）
                complete_mnemonic_string = bip39.mnemonic_from_bytes(entropy)
                complete_mnemonic = complete_mnemonic_string.split()
                
                logger.info(f"NFCReader: Complete mnemonic from embit.bip39: {complete_mnemonic}")
                logger.debug(f"NFCReader: Generated {len(complete_mnemonic)} words from {len(entropy)} bytes entropy")
                
                # 最後の単語のインデックスを取得
                wordlist = Seed.get_wordlist(SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
                last_word = complete_mnemonic[-1]
                checksum_index = wordlist.index(last_word)
                
                logger.info(f"NFCReader: Last word (checksum): '{last_word}' -> index {checksum_index}")
                logger.info(f"NFCReader: ✓ Checksum calculation completed using embit.bip39 (same as CompactSeedQR)")
                logger.info(f"NFCReader: === Method Verification ===")
                logger.info(f"NFCReader: Used same embit.bip39.mnemonic_to_bytes() -> embit.bip39.mnemonic_from_bytes() as CompactSeedQR")
                logger.info(f"NFCReader: This checksum index should match CompactSeedQR checksum index")
                return checksum_index
                
            except Exception as e:
                logger.error(f"NFCReader: Error using embit.bip39 for checksum calculation: {e}")
                return -1
            
        except Exception as e:
            logger.error(f"NFCReader: Error calculating checksum using QR method: {e}")
            return -1
    
    def _verify_fingerprint(self, seed: Seed, expected_fingerprint: bytes) -> bool:
        """シードのフィンガープリントを検証"""
        try:
            actual_fingerprint = seed.get_fingerprint()
            expected_fingerprint_hex = binascii.hexlify(expected_fingerprint).decode('utf-8')
            
            logger.debug(f"Expected fingerprint: {expected_fingerprint_hex}")
            logger.debug(f"Actual fingerprint: {actual_fingerprint}")
            
            return actual_fingerprint == expected_fingerprint_hex
            
        except Exception as e:
            logger.error(f"Error verifying fingerprint: {e}")
            return False
    
    def _clear_sector(self, sector_num: int) -> bool:
        """指定されたセクタのブロックを削除（0x00で埋める）"""
        try:
            # セクタの1、2、3番目のブロックを0x00で埋める（管理ブロック→シードブロックの順）
            zero_block = bytes(16)  # 16バイトの0x00
            
            blocks_to_clear = [
                sector_num * self.SECTOR_SIZE,      # 管理ブロック（sector*4）
                sector_num * self.SECTOR_SIZE + 1,  # シードブロック1（sector*4+1）
                sector_num * self.SECTOR_SIZE + 2   # シードブロック2（sector*4+2）
            ]
            
            for block_num in blocks_to_clear:
                # トレーラーブロック（sector*4+3）は触らない
                if (block_num % 4) == 3:
                    logger.warning(f"Skipping trailer block {block_num}")
                    continue
                
                if not self._authenticate_block(block_num):
                    logger.error(f"Authentication failed for block {block_num}")
                    return False
                
                self._nfc_module.mifare_classic_write_block(block_num, zero_block)
                logger.info(f"Cleared block {block_num}")
                time.sleep(0.1)
            
            logger.info(f"Successfully cleared sector {sector_num}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to clear sector {sector_num}: {e}")
            return False
