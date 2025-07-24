#!/usr/bin/env python3
"""
CompactSeedQRから読み込んだニーモニックを使ってNFCカードと比較する
ログから読み込んだニーモニック: onion wood atom dawn nest carbon domain achieve milk smart deputy polar
"""

import sys
import os

# SeedSignerのパスを追加
sys.path.insert(0, 'src')

def compare_with_nfc():
    """CompactSeedQRから読み込んだニーモニックとNFCカードの比較"""
    print("=== CompactSeedQR vs NFC Comparison ===")
    
    # ログから読み込んだニーモニック
    qr_mnemonic = [
        "onion", "wood", "atom", "dawn", "nest", "carbon", 
        "domain", "achieve", "milk", "smart", "deputy", "polar"
    ]
    
    print(f"CompactSeedQR mnemonic ({len(qr_mnemonic)} words):")
    for i, word in enumerate(qr_mnemonic, 1):
        print(f"  {i:2d}: {word}")
    
    # 最後の単語（チェックサム）の詳細
    last_word = qr_mnemonic[-1]
    print(f"\nChecksum word: '{last_word}' (expected index: 1339)")
    
    try:
        from seedsigner.models.seed import Seed
        from seedsigner.models.settings import SettingsConstants
        from embit import bip39
        
        wordlist = Seed.get_wordlist(SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
        last_word_index = wordlist.index(last_word)
        print(f"Actual index: {last_word_index}")
        
        # エントロピーを計算
        mnemonic_string = " ".join(qr_mnemonic)
        entropy = bip39.mnemonic_to_bytes(mnemonic_string)
        print(f"\nEntropy from CompactSeedQR: {entropy.hex()}")
        print(f"Entropy length: {len(entropy)} bytes")
        
        # 検証
        regenerated = bip39.mnemonic_from_bytes(entropy)
        print(f"Regenerated mnemonic: {regenerated}")
        
        if mnemonic_string == regenerated:
            print("✓ Mnemonic validation successful")
        else:
            print("✗ Mnemonic validation failed")
        
        print(f"\n=== NFCカードとの比較手順 ===")
        print(f"1. SeedSignerで「Seeds」→「Load a seed」→「NFC」を選択")
        print(f"2. NFCカードを読み込み")
        print(f"3. DEBUG Logを確認してから以下のログを確認:")
        print(f"")
        print(f"【期待されるNFCReaderログ】")
        print(f"NFCReader: This entropy should match CompactSeedQR entropy: {entropy.hex()}")
        print(f"NFCReader: This mnemonic should match CompactSeedQR: {mnemonic_string}")
        print(f"NFCReader: This checksum should match CompactSeedQR: 'polar' (index 1339)")
        print(f"NFCReader: ✓ Both NFC and CompactSeedQR use identical embit.bip39 methods")
        print(f"")
        print(f"【比較ポイント】")
        print(f"✓ エントロピー一致: {entropy.hex()}")
        print(f"✓ ニーモニック一致: {mnemonic_string}")
        print(f"✓ チェックサム一致: 'polar' (index 1339)")
        print(f"✓ 同じembit.bip39メソッド使用")
        print(f"")
        print(f"4. 両方で同じ結果が得られることを確認")
        
        # 11語からのチェックサム計算も表示
        print(f"\n=== 11語からのチェックサム計算 ===")
        partial_words = qr_mnemonic[:-1]
        print(f"Partial mnemonic (11 words): {' '.join(partial_words)}")
        
        # 手動でエントロピーを計算（NFCReaderと同じ方法）
        indices = []
        for word in partial_words:
            index = wordlist.index(word)
            indices.append(index)
        
        print(f"Word indices: {indices}")
        
        # 11語のインデックスから120ビットのエントロピーを計算
        entropy_bits = ""
        for index in indices:
            entropy_bits += format(index, '011b')  # 各語は11ビット
        
        # 132ビットを120ビット（15バイト）に切り詰め
        entropy_bits_120 = entropy_bits[:120]
        
        # バイト列に変換
        partial_entropy_bytes = bytearray()
        for i in range(0, 120, 8):
            byte_bits = entropy_bits_120[i:i+8]
            if len(byte_bits) == 8:
                partial_entropy_bytes.append(int(byte_bits, 2))
        
        partial_entropy = bytes(partial_entropy_bytes)
        print(f"Calculated partial entropy: {partial_entropy.hex()}")
        
        # エントロピーから完全なニーモニックを再生成
        regenerated_from_partial = bip39.mnemonic_from_bytes(partial_entropy)
        regenerated_partial_words = regenerated_from_partial.split()
        regenerated_last_word = regenerated_partial_words[-1]
        
        print(f"Regenerated from 11 words: {regenerated_from_partial}")
        print(f"Regenerated checksum word: '{regenerated_last_word}'")
        
        if regenerated_last_word == last_word:
            print("✓ 11語からのチェックサム計算も正常")
        else:
            print(f"✗ チェックサム不一致: '{regenerated_last_word}' != '{last_word}'")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    compare_with_nfc()
