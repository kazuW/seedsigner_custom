#!/usr/bin/env python3
"""
BIP39構造分析とエントロピー再構築テスト

12単語BIP39の構造：
- 11単語 × 11ビット = 121ビット（エントロピー）
- 12番目の単語：7ビット（エントロピー）+ 4ビット（チェックサム）= 11ビット
- 合計：128ビット（エントロピー）+ 4ビット（チェックサム）= 132ビット

NFCストレージの問題：
- NFCには16バイト（128ビット）のデータと管理ブロックのチェックサムが別々に保存
- 12番目の単語の7ビットエントロピー部分が失われている可能性
"""

import sys
import os
import logging
import binascii

# プロジェクトのルートディレクトリをパスに追加
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants

# ログ設定
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

def analyze_bip39_structure():
    """BIP39構造の詳細分析"""
    try:
        from embit import bip39
        
        print("=== BIP39構造分析 ===")
        print("12単語BIP39構造:")
        print("  - 11単語 × 11ビット = 121ビット（エントロピー）")
        print("  - 12番目の単語：7ビット（エントロピー）+ 4ビット（チェックサム）")
        print("  - 合計：128ビット（エントロピー）+ 4ビット（チェックサム）= 132ビット")
        print()
        
        # テスト用の128ビットエントロピーを生成
        test_entropy = bytes.fromhex("123456789abcdef0123456789abcdef0")
        print(f"テストエントロピー（128ビット）: {binascii.hexlify(test_entropy).decode('utf-8')}")
        
        # embit.bip39でニーモニックを生成
        mnemonic_string = bip39.mnemonic_from_bytes(test_entropy)
        mnemonic = mnemonic_string.split()
        print(f"BIP39ニーモニック: {' '.join(mnemonic)}")
        print(f"単語数: {len(mnemonic)}")
        print()
        
        # 単語をインデックスに変換
        wordlist = Seed.get_wordlist(SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
        word_indices = [wordlist.index(word) for word in mnemonic]
        print("単語インデックス:")
        for i, (word, index) in enumerate(zip(mnemonic, word_indices)):
            print(f"  {i+1:2d}: '{word}' -> {index:4d} (0x{index:03X}) [{index:011b}]")
        print()
        
        # ビット構造分析
        print("=== ビット構造分析 ===")
        
        # 各単語を11ビットに変換
        all_bits = ""
        for i, index in enumerate(word_indices):
            word_bits = f"{index:011b}"
            all_bits += word_bits
            print(f"単語{i+1:2d}: {word_bits} ({index:4d})")
        
        print(f"\n結合ビット列（{len(all_bits)}ビット）: {all_bits}")
        
        # エントロピー部分とチェックサム部分に分割
        entropy_bits = all_bits[:128]  # 最初の128ビットがエントロピー
        checksum_bits = all_bits[128:]  # 残りの4ビットがチェックサム
        
        print(f"\nエントロピー部分（128ビット）: {entropy_bits}")
        print(f"チェックサム部分（4ビット）:   {checksum_bits}")
        
        # エントロピーをバイト配列に変換
        entropy_int = int(entropy_bits, 2)
        reconstructed_entropy = entropy_int.to_bytes(16, 'big')
        print(f"\n再構築エントロピー: {binascii.hexlify(reconstructed_entropy).decode('utf-8')}")
        print(f"元のエントロピー:   {binascii.hexlify(test_entropy).decode('utf-8')}")
        print(f"一致: {reconstructed_entropy == test_entropy}")
        
        # 12番目の単語の詳細分析
        print(f"\n=== 12番目の単語詳細分析 ===")
        last_word_index = word_indices[-1]
        last_word_bits = f"{last_word_index:011b}"
        last_word_entropy_bits = last_word_bits[:7]   # 上位7ビット
        last_word_checksum_bits = last_word_bits[7:]  # 下位4ビット
        
        print(f"12番目の単語: '{mnemonic[-1]}' -> {last_word_index} (0x{last_word_index:03X})")
        print(f"  全体:           {last_word_bits}")
        print(f"  エントロピー:   {last_word_entropy_bits} ({int(last_word_entropy_bits, 2):3d})")
        print(f"  チェックサム:   {last_word_checksum_bits} ({int(last_word_checksum_bits, 2):2d})")
        
        return {
            'test_entropy': test_entropy,
            'mnemonic': mnemonic,
            'word_indices': word_indices,
            'reconstructed_entropy': reconstructed_entropy,
            'last_word_index': last_word_index,
            'last_word_entropy_value': int(last_word_entropy_bits, 2),
            'last_word_checksum_value': int(last_word_checksum_bits, 2)
        }
        
    except Exception as e:
        logger.error(f"BIP39構造分析エラー: {e}")
        return None

def simulate_nfc_storage_corruption():
    """NFCストレージ破損のシミュレーション"""
    print("\n=== NFCストレージ破損シミュレーション ===")
    
    # 正常なBIP39分析結果を取得
    analysis = analyze_bip39_structure()
    if not analysis:
        return
    
    print(f"元のエントロピー（128ビット）: {binascii.hexlify(analysis['test_entropy']).decode('utf-8')}")
    print(f"元のニーモニック: {' '.join(analysis['mnemonic'])}")
    print(f"元の12番目の単語: '{analysis['mnemonic'][-1]}' -> index {analysis['last_word_index']}")
    
    # NFCストレージの問題をシミュレート
    # 実際の問題：最後のバイトが0x53→0x00に破損
    original_entropy = analysis['test_entropy']
    corrupted_entropy = bytearray(original_entropy)
    corrupted_entropy[-1] = 0x00  # 最後のバイトを0x00に変更（0xF0 → 0x00）
    
    print(f"\n=== 破損シミュレーション ===")
    print(f"破損エントロピー（128ビット）: {binascii.hexlify(corrupted_entropy).decode('utf-8')}")
    
    try:
        from embit import bip39
        
        # 破損エントロピーからニーモニックを生成
        corrupted_mnemonic_string = bip39.mnemonic_from_bytes(bytes(corrupted_entropy))
        corrupted_mnemonic = corrupted_mnemonic_string.split()
        
        print(f"破損ニーモニック:             {' '.join(corrupted_mnemonic)}")
        print(f"破損12番目の単語:           '{corrupted_mnemonic[-1]}'")
        
        wordlist = Seed.get_wordlist(SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
        corrupted_last_word_index = wordlist.index(corrupted_mnemonic[-1])
        print(f"破損チェックサムインデックス:   {corrupted_last_word_index}")
        
        # NFCに保存されるデータ（破損エントロピー + 元のチェックサム）
        nfc_stored_entropy = bytes(corrupted_entropy)  # 破損した16バイト
        nfc_stored_checksum = analysis['last_word_index']  # 元の正しいチェックサム
        
        print(f"\n=== NFC保存データ ===")
        print(f"NFC保存エントロピー: {binascii.hexlify(nfc_stored_entropy).decode('utf-8')}")
        print(f"NFC保存チェックサム: {nfc_stored_checksum} -> '{wordlist[nfc_stored_checksum]}'")
        
        # === 修正ロジック ===
        print(f"\n=== 修正ロジック適用 ===")
        
        # 正しいアプローチ：管理ブロックのチェックサムから12番目の単語の情報を使用
        # 1. チェックサムから12番目の単語のエントロピー部分（7ビット）を抽出
        checksum_word_index = nfc_stored_checksum
        checksum_word_bits = f"{checksum_word_index:011b}"
        last_word_entropy_7bits = checksum_word_bits[:7]  # 上位7ビット
        
        print(f"管理ブロックチェックサム: {checksum_word_index} -> '{wordlist[checksum_word_index]}'")
        print(f"チェックサム単語ビット: {checksum_word_bits}")
        print(f"12番目の単語エントロピー（7ビット）: {last_word_entropy_7bits}")
        
        # 2. NFCエントロピーから最初の121ビット（11単語分）を抽出
        entropy_bits = bin(int.from_bytes(nfc_stored_entropy, 'big'))[2:].zfill(128)
        entropy_121bits = entropy_bits[:121]  # 最初の121ビット
        
        print(f"NFCエントロピー（破損）: {entropy_bits}")
        print(f"11単語分（121ビット）: {entropy_121bits}")
        
        # 3. 121ビット + 7ビット = 128ビットの完全なエントロピーを再構築
        complete_entropy_bits = entropy_121bits + last_word_entropy_7bits
        complete_entropy_int = int(complete_entropy_bits, 2)
        reconstructed_entropy = complete_entropy_int.to_bytes(16, 'big')
        
        print(f"完全エントロピー（128ビット）: {complete_entropy_bits}")
        print(f"再構築エントロピー（バイト）: {binascii.hexlify(reconstructed_entropy).decode('utf-8')}")
        
        # 4. 再構築されたエントロピーから正しいニーモニックを生成
        correct_mnemonic_string = bip39.mnemonic_from_bytes(reconstructed_entropy)
        correct_mnemonic = correct_mnemonic_string.split()
        
        print(f"修正ニーモニック:   {' '.join(correct_mnemonic)}")
        print(f"修正12番目の単語: '{correct_mnemonic[-1]}'")
        
        # 6. 検証
        print(f"\n=== 修正結果検証 ===")
        print(f"元のエントロピー: {binascii.hexlify(analysis['test_entropy']).decode('utf-8')}")
        print(f"修正エントロピー: {binascii.hexlify(reconstructed_entropy).decode('utf-8')}")
        print(f"エントロピー一致: {analysis['test_entropy'] == reconstructed_entropy}")
        
        print(f"\n元のニーモニック: {' '.join(analysis['mnemonic'])}")
        print(f"修正ニーモニック: {' '.join(correct_mnemonic)}")
        print(f"ニーモニック一致: {analysis['mnemonic'] == correct_mnemonic}")
        
        if analysis['mnemonic'] == correct_mnemonic:
            print("\n✓ 修正ロジックは正常に動作しています")
            print("✓ NFCの破損エントロピーから正しいニーモニックを復元できました")
        else:
            print("\n✗ 修正ロジックに問題があります")
            
    except Exception as e:
        logger.error(f"NFCシミュレーションエラー: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("BIP39構造分析とエントロピー再構築テスト")
    print("=" * 50)
    
    analyze_bip39_structure()
    simulate_nfc_storage_corruption()
