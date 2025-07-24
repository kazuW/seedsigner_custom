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
            calculated_checksum_index = self._calculate_checksum_index(mnemonic[:-1], num_words)
            if calculated_checksum_index != checksum:
                logger.error(f"BIP39 checksum verification failed: calculated {calculated_checksum_index}, stored {checksum}")
                logger.error(f"This means the stored seed is not a valid BIP39 mnemonic")
                return None
            
            logger.debug(f"BIP39 checksum verification successful: calculated {calculated_checksum_index} == stored {checksum}")
            
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
            calculated_checksum_index = self._calculate_checksum_index(mnemonic[:-1], num_words)
            if calculated_checksum_index != checksum:
                logger.error(f"BIP39 checksum verification failed: calculated {calculated_checksum_index}, stored {checksum}")
                logger.error(f"This means the stored seed is not a valid BIP39 mnemonic")
                return None
            
            logger.debug(f"BIP39 checksum verification successful: calculated {calculated_checksum_index} == stored {checksum}")
            
            logger.debug(f"Successfully decompressed {num_words}-word mnemonic")
            return mnemonic
            
        except Exception as e:
            logger.error(f"Error decompressing seed to mnemonic: {e}")
            return None
    
    def _calculate_checksum_index(self, partial_mnemonic: List[str], total_words: int) -> int:
        """部分的なニーモニックからチェックサムインデックスを計算"""
        try:
            logger.debug(f"Calculating BIP39 checksum for {len(partial_mnemonic)} words (expecting {total_words} total)")
            logger.debug(f"Input words: {partial_mnemonic}")
            
            # BIP39の仕様に従ってエントロピーを計算
            wordlist = Seed.get_wordlist(SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
            
            # 単語をインデックスに変換
            indices = []
            for word in partial_mnemonic:
                try:
                    index = wordlist.index(word)
                    indices.append(index)
                    logger.debug(f"Word '{word}' -> index {index}")
                except ValueError:
                    logger.error(f"Word '{word}' not found in wordlist")
                    return -1
            
            # インデックスをビット文字列に変換
            bit_string = ""
            for index in indices:
                bit_string += format(index, '011b')
            
            logger.debug(f"Combined bit string: {bit_string} (length: {len(bit_string)} bits)")
            
            # BIP39チェックサム計算の正しい方法：
            # 1. 11語のビット文字列（121ビット）を16バイトにパディング
            # 2. そのバイトデータのSHA256を計算
            # 3. ハッシュの最初の4ビットがチェックサム
            # 4. 最後の単語は：元の最後のビット（足りない分は0パディング）+ チェックサム4ビット
            
            checksum_bits = total_words // 3
            logger.debug(f"Checksum bits needed: {checksum_bits}")
            
            # 11語のビット文字列を128ビット（16バイト）にパディング
            # 121ビット → 128ビットに拡張（末尾7ビットを0で埋める）
            padded_bit_string = bit_string.ljust(128, '0')
            logger.debug(f"Padded bit string to 128 bits: {padded_bit_string}")
            
            # 128ビットをバイト配列に変換
            entropy_bytes = bytearray()
            for i in range(0, 128, 8):
                byte_str = padded_bit_string[i:i+8]
                entropy_bytes.append(int(byte_str, 2))
            
            logger.debug(f"128-bit entropy bytes: {[hex(b) for b in entropy_bytes]}")
            
            # エントロピーからSHA256を計算
            import hashlib
            hash_bytes = hashlib.sha256(bytes(entropy_bytes)).digest()
            logger.debug(f"SHA256 hash: {hash_bytes.hex()}")
            
            # チェックサムビットを抽出（最初の4ビット）
            hash_bit_string = ''.join(format(b, '08b') for b in hash_bytes)
            checksum_string = hash_bit_string[:checksum_bits]
            logger.debug(f"Checksum string from hash: {checksum_string}")
            
            # 最後の単語のインデックスを計算
            # 元の121ビットの最後から11ビット目以降 + チェックサム4ビット = 11ビット
            remaining_entropy_bits = 11 - checksum_bits  # 7ビット
            
            # 元のビット文字列から最後の7ビットを取得
            if len(bit_string) >= remaining_entropy_bits:
                # 121ビットの最後の7ビットを取得
                remaining_entropy = bit_string[-remaining_entropy_bits:]
            else:
                # 足りない場合は0でパディング
                remaining_entropy = bit_string.ljust(remaining_entropy_bits, '0')
            
            logger.debug(f"Remaining entropy bits: {remaining_entropy_bits}, remaining entropy: {remaining_entropy}")
            
            last_word_bits = remaining_entropy + checksum_string
            checksum_index = int(last_word_bits, 2)
            
            logger.debug(f"Last word bits: {last_word_bits} -> checksum index: {checksum_index}")
            
            return checksum_index
            
        except Exception as e:
            logger.error(f"Error calculating checksum: {e}")
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
