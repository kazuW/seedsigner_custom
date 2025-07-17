import board
import busio
from adafruit_pn532.i2c import PN532_I2C
import adafruit_pn532
import time

# PN532モジュールの初期化
i2c = busio.I2C(board.SCL, board.SDA)
pn532 = PN532_I2C(i2c, debug=False, irq=None)
pn532.SAM_configuration()

# デフォルトKey A（全FF、工場出荷時設定）
key_a = b'\xFF\xFF\xFF\xFF\xFF\xFF'

while True:
    # NFCカードの検出を待つ
    uid = pn532.read_passive_target(timeout=0.5)

    if uid is not None:
        print("NFCカードが検出されました!")
        print("UID:", [hex(i) for i in uid])
        break

# 全ブロック（0〜63）を順次読み出し
for block_number in range(64):
    sector_number = block_number // 4
    block_index = block_number % 4

    # 各セクタごとに認証（セクタ内の任意のブロック番号を指定すればOK）
    if block_index == 0:
        print(f'\n=== Sector {sector_number} ===')

    # 認証（セクタ内どのブロックを指定してもよいが、通常は先頭のblock）
    success = pn532.mifare_classic_authenticate_block(
        uid, block_number, 0x60, key_a
    )

    if not success:
        print(f'Block {block_number:2}: 認証失敗 ⚠️')
        continue

    # データ読み出し
    block_data = pn532.mifare_classic_read_block(block_number)
    if block_data is None:
        print(f'Block {block_number:2}: 読み取り失敗 ❌')
    else:
        hex_data = ' '.join('{:02X}'.format(x) for x in block_data)
        print(f'Block {block_number:2}: {hex_data}')

    # 少し待つ
    time.sleep(0.1)
