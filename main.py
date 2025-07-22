import re
import ndef
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from smartcard.System import readers
import os
import binascii

rnd_a_clear = os.urandom(16)  # random 16 bytes for sending nonce


class NFCSession:
    def __init__(self):
        r = readers()
        if not r:
            raise Exception("No reader found.")
        self.connection = r[0].createConnection()
        self.connection.connect()

    def send_apdu(self, hex_command):
        apdu = [int(hex_command[i : i + 2], 16) for i in range(0, len(hex_command), 2)]
        response, sw1, sw2 = self.connection.transmit(apdu)
        return "".join(f"{x:02X}" for x in response + [sw1, sw2])


def aes_cmac(key, data):
    cobj = CMAC.new(key, ciphermod=AES)
    cobj.update(data)
    return cobj.digest()


def ntag424_calc_mac(session_keys: dict, command: bytes, data: bytes) -> bytes:
    command_counter = session_keys["command_counter"]  # integer
    ti = session_keys["ti"]  # 4 bytes
    mac_key = session_keys["mac"]  # 16 bytes

    mac_input_header = bytes(
        [
            command,
            command_counter & 0xFF,
            (command_counter >> 8) & 0xFF,
            ti[0],
            ti[1],
            ti[2],
            ti[3],
        ]
    )

    mac_input = mac_input_header + data

    mac = aes_cmac(mac_key, mac_input)
    session_keys["command_counter"] += 1
    # Extract every second byte starting from index 1 (bytes 1,3,5,...,15)
    return bytes(mac[1 + (i * 2)] for i in range(8))


def derive_session_keys(key, rnd_a_clear, rnd_b_clear, ti):
    sv1 = bytes(
        [
            0xA5,
            0x5A,
            0x00,
            0x01,
            0x00,
            0x80,
            rnd_a_clear[0],
            rnd_a_clear[1],
            rnd_a_clear[2] ^ rnd_b_clear[0],
            rnd_a_clear[3] ^ rnd_b_clear[1],
            rnd_a_clear[4] ^ rnd_b_clear[2],
            rnd_a_clear[5] ^ rnd_b_clear[3],
            rnd_a_clear[6] ^ rnd_b_clear[4],
            rnd_a_clear[7] ^ rnd_b_clear[5],
            *rnd_b_clear[6:16],
            *rnd_a_clear[8:16],
        ]
    )

    sv2 = bytes(
        [
            0x5A,
            0xA5,
            0x00,
            0x01,
            0x00,
            0x80,
            rnd_a_clear[0],
            rnd_a_clear[1],
            rnd_a_clear[2] ^ rnd_b_clear[0],
            rnd_a_clear[3] ^ rnd_b_clear[1],
            rnd_a_clear[4] ^ rnd_b_clear[2],
            rnd_a_clear[5] ^ rnd_b_clear[3],
            rnd_a_clear[6] ^ rnd_b_clear[4],
            rnd_a_clear[7] ^ rnd_b_clear[5],
            *rnd_b_clear[6:16],
            *rnd_a_clear[8:16],
        ]
    )

    # damn I love crypto

    encryption_key = aes_cmac(key, sv1)
    mac_key = aes_cmac(key, sv2)

    return {
        "ti": ti,
        "encryption": encryption_key,
        "mac": mac_key,
        "command_counter": 0,
    }


def xor_16byte(a: bytes, b: bytes) -> bytes:
    if len(a) != 16 or len(b) != 16:
        raise ValueError("Both inputs must be exactly 16 bytes.")
    return bytes([x ^ y for x, y in zip(a, b)])


def jamcrc_4byte(data: bytes) -> str:
    if len(data) != 16:
        raise ValueError("Input must be exactly 16 bytes.")
    crc = binascii.crc32(data) ^ 0xFFFFFFFF
    crc_bytes = crc.to_bytes(4, byteorder="big")
    return crc_bytes.hex()


def aes_decode(iv, key, input_data):
    if iv is None:
        iv = bytes([0] * 16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(input_data)


def rotate_left_1byte(data):
    return data[1:] + data[:1]


def prepare_concat(rnd_b_clear):
    if len(rnd_b_clear) != 16:
        raise ValueError("rnd_b_clear must be 16 bytes")
    rotated_rnd_b = rotate_left_1byte(rnd_b_clear)
    return rnd_a_clear + rotated_rnd_b


def aes_encode(iv, key, input_data):
    if iv is None:
        iv = bytes([0] * 16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(input_data)


def ask_choice():
    while True:
        choice = input(
            "Choose an option:\n1. Personalize ntag with URL and SDM\nOR\n2. Change ntag keys\n> "
        ).strip()
        if choice == "1":
            return False
        elif choice == "2":
            return True
        else:
            print("Invalid choice. Enter 1 or 2.")


def keys_choice():
    while True:
        choice = input(
            "Choose an option:\n0. Change key 0\n1. Change key 1\n2. Change key 2\n3. Change key 3\n4. Change key 4\n> "
        ).strip()
        if int(choice) < 5:
            return int(choice)
        else:
            print("Invalid choice. Enter number less than 5.")


def ask_choice_ndef():
    while True:
        choice = input(
            "Choose an option to go in URL:\n1. picc_data (encrypted UID+CTR) and cmac\nOR\n2. uid, counter, & cmac\n> "
        ).strip()
        if choice == "1":
            return True
        elif choice == "2":
            return False
        else:
            print("Invalid choice. Enter 1 or 2.")


def calculate_keydata(keyno, old_key, new_key, version, session_keys):
    ver = f"{version:02X}"

    if keyno != 0:
        final_key = xor_16byte(new_key, old_key)
        s = jamcrc_4byte(new_key)
        crc_reversed = "".join([s[i : i + 2] for i in range(0, len(s), 2)][::-1])
        final_key_padding = (
            final_key.hex() + ver + crc_reversed + "8000000000000000000000"
        )  # manually adding padding bc it'll always be the same length anyways..
    else:
        final_key = new_key
        final_key_padding = (
            final_key.hex() + ver + "800000000000000000000000000000"
        )  # same here

    key_hex = bytes.fromhex(final_key_padding)
    iv = bytes.fromhex(
        "A55A"  # sending IV prefix
        + session_keys["ti"].hex()
        + f"{(session_keys["command_counter"] & 0xFF):02X}"
        + f"{((session_keys["command_counter"] >> 8) & 0xFF):02X}"
        + "0000000000000000"
    )
    encr_iv = aes_encode(None, session_keys["encryption"], iv)
    encr_key = aes_encode(encr_iv, session_keys["encryption"], key_hex)
    cmac = ntag424_calc_mac(
        session_keys, 0xC4, bytes.fromhex(f"{keyno:02X}{encr_key.hex()}")
    )
    command = (
        "90"
        + "C4"
        + "0000"
        + f"{int(len(key_hex) + 8 + 1):02X}"
        + f"{keyno:02X}"
        + encr_key.hex()
        + cmac.hex()
        + "00"
    )
    return command


def change_fs(
    session_keys, options, accessrights, sdmopt, sdmaccess, offsets, picc_data
):
    iv = bytes.fromhex(
        "A55A"  # sending IV prefix
        + session_keys["ti"].hex()
        + f"{(session_keys["command_counter"] & 0xFF):02X}"
        + f"{((session_keys["command_counter"] >> 8) & 0xFF):02X}"
        + "0000000000000000"
    )
    encr_iv = aes_encode(None, session_keys["encryption"], iv)
    data1 = "".join([offsets[0][i : i + 2] for i in range(0, len(offsets[0]), 2)][::-1])
    data2 = "".join([offsets[1][i : i + 2] for i in range(0, len(offsets[1]), 2)][::-1])
    # why are you reading this
    if picc_data:
        data3 = "".join(
            [offsets[1][i : i + 2] for i in range(0, len(offsets[1]), 2)][::-1]
        )
    else:
        data3 = "".join(
            [offsets[2][i : i + 2] for i in range(0, len(offsets[2]), 2)][::-1]
        )

    if picc_data:
        data = bytes.fromhex(
            f"{options:02X}{accessrights}{sdmopt:02X}{sdmaccess:02X}{data1}{data2}{data3}80"
        )  # 16 byte
    else:
        data = bytes.fromhex(
            f"{options:02X}{accessrights}{sdmopt:02X}{sdmaccess:02X}{data1}{data2}{data3}{data3}8000000000000000000000000000"
        )  # 32 byte
    encr_data = aes_encode(encr_iv, session_keys["encryption"], data)
    cmac = ntag424_calc_mac(session_keys, 0x5F, bytes.fromhex(f"02{encr_data.hex()}"))
    command = (
        "90"
        + "5F"
        + "0000"
        + f"{int(len(data) + 8 + 1):02X}"
        + "02"
        + encr_data.hex()
        + cmac.hex()
        + "00"
    )
    return command


def ask_url():
    while True:
        url = input(
            "Enter the base URL (example: https://example.com/website):\n> "
        ).strip()
        url = url.replace(" ", "")
        if re.match(r"^https?://[^/]+/.+", url):
            return url
        else:
            print(
                "Invalid URL. Ensure it starts with http:// or https:// and has a path after the domain."
            )


def confirm_url(final_url):
    print(f"\nIs this good?\n\n{final_url}\n")
    confirm = input("Type 'yes' to confirm: ").strip().lower()
    return confirm == "yes"


def find_param_value_offset(payload_bytes, param_name):
    # Find the offset of param_name= in the bytes and return index of the value start (after '=')
    param_str = param_name + "="
    param_bytes = param_str.encode("utf-8")
    index = payload_bytes.find(param_bytes)
    if index == -1:
        return None
    return index + len(param_bytes)


def authenticate(nfc, key):
    print("Authenticating with card..")
    nfc.send_apdu("00A4040C07D276000085010100")  # select
    rndb_enc_s = nfc.send_apdu("9071000002000000")
    rndb_enc = bytes.fromhex(rndb_enc_s[:-4])
    # start authentication, request encrypted rndb from card
    if len(rndb_enc_s) == 36:
        if len(key) == 32:
            key = bytes.fromhex(key)
        else:
            print("using default key")
            key = bytes.fromhex("00000000000000000000000000000000")
        rndb_clr = aes_decode(None, key, rndb_enc)
        concat_result = prepare_concat(rndb_clr)  # rnda || rndb'
        rndb_rnda_concat_encr = aes_encode(None, key, concat_result)
        resp = nfc.send_apdu("90AF000020" + rndb_rnda_concat_encr.hex().upper() + "00")
        if len(resp) == 68:
            resp_enc = bytes.fromhex(resp[:-4])
            resp_clr = aes_decode(None, key, resp_enc)
            ti = resp_clr[:4]
            session_keys = derive_session_keys(key, rnd_a_clear, rndb_clr, ti)
            print("authentication success")
            return session_keys
        else:
            print("authentication error:", resp[-4:], "wrong key maybe?")
    else:
        print("error with authentication:", rndb_enc[-4:])


def main():
    if ask_choice():
        key_num = keys_choice()

        key0 = input("input key 0: ").replace(" ", "")
        if len(key0) == 32:
            old_key = None
            if key_num != 0:
                old_key = input(f"input old key {key_num}: ").replace(" ", "")
                if len(old_key) != 32:
                    print("error in length of old key")
                    return

            new_key = input(f"input new key {key_num}: ").replace(" ", "")
            nfc = NFCSession()
            session_keys = authenticate(nfc, key0)

            command = calculate_keydata(
                key_num,
                bytes.fromhex(old_key) if old_key else None,
                bytes.fromhex(new_key),
                1,
                session_keys,
            )
            change_key = nfc.send_apdu(command)
            if change_key[-4:] != "9100":
                print("error in changing key")
                return
            print("Successfully changed key")

        else:
            print("error in key 0 length")

    else:
        picc_data = ask_choice_ndef()
        base_url = ask_url()

        if picc_data:
            sample_url = f"{base_url}?picc_data=" + "X" * 32 + "&cmac=" + "X" * 16
        else:
            sample_url = (
                f"{base_url}?uid=" + "X" * 14 + "&ctr=" + "X" * 6 + "&cmac=" + "X" * 16
            )

        if not confirm_url(sample_url):
            print("Cancelled by user")
            return

        # Create NDEF URI record
        ndef_record = ndef.UriRecord(sample_url)
        ndef_payload = b"".join(ndef.message_encoder([ndef_record]))

        # Prefix with 0x00 and payload length byte
        prefix = bytes([0x00, len(ndef_payload)])
        full_payload = prefix + ndef_payload

        # Find offsets of params values including the prefix bytes (offset 0 and 1)
        # so add +2 to all found positions
        offsets = {}
        if picc_data:
            offsets["picc_data"] = find_param_value_offset(ndef_payload, "picc_data")
            offsets["cmac"] = find_param_value_offset(ndef_payload, "cmac")
            # add 2 for prefix
            offsets = {k: v + 2 for k, v in offsets.items()}
        else:
            offsets["uid"] = find_param_value_offset(ndef_payload, "uid")
            offsets["ctr"] = find_param_value_offset(ndef_payload, "ctr")
            offsets["cmac"] = find_param_value_offset(ndef_payload, "cmac")
            offsets = {k: v + 2 for k, v in offsets.items()}

        print(f"\nFull NDEF Payload Hex (with prefix):\n{full_payload.hex()}")
        print("\nOffsets within payload (including prefix):")
        for k, v in offsets.items():
            print(f"{k}: {v}")
        # start with authentication and selection
        nfc = NFCSession()
        key = input("Key 0? (16 bytes, default 00000..): ").replace(" ", "")
        session_keys = authenticate(nfc, key)
        if session_keys:
            bytes_to_write = len(full_payload)
            apdu_payload = (
                "02"  # file num
                + "000000"  # offset within file to write bytes
                + f"{bytes_to_write:02X}"
                + "0000"  # endian of size of payload
                + full_payload.hex()  # payload
            )
            payload_len = int(
                len(apdu_payload) / 2
            )  # just byte length not character length
            assembled_apdu_payload = (
                "90"
                + "8D"  # command to write file
                + "0000"
                + f"{payload_len:02X}"
                + apdu_payload
                + "00"  # Le
            )
            write_ndef_status = nfc.send_apdu(assembled_apdu_payload)
            if write_ndef_status == "9100":
                session_keys = authenticate(
                    nfc, key
                )  # gotta authenticate again for some reason
                if picc_data:
                    prepared_offsets = [
                        offsets["picc_data"].to_bytes(3, "big").hex(),
                        offsets["cmac"].to_bytes(3, "big").hex(),
                    ]
                    command = change_fs(
                        session_keys,
                        0x40,
                        "00E0",
                        0xC1,
                        0xF000,
                        prepared_offsets,
                        picc_data,
                    )
                else:
                    prepared_offsets = [
                        offsets["uid"].to_bytes(3, "big").hex(),
                        offsets["ctr"].to_bytes(3, "big").hex(),
                        offsets["cmac"].to_bytes(3, "big").hex(),
                    ]
                    command = change_fs(
                        session_keys,
                        0x40,
                        "00E0",
                        0xC1,
                        0xF0E0,
                        prepared_offsets,
                        picc_data,
                    )
                write_file_settings = nfc.send_apdu(command)
                if write_file_settings[-4:] == "9100":
                    print("SUCCESS")
                else:
                    print("error writting the SDM data:", write_file_settings[-4:])
            else:
                print("error:", write_ndef_status)
        else:
            return


if __name__ == "__main__":
    main()
