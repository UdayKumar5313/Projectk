import secrets
import string
import hashlib
import os
import random
import base64
import math
import datetime
import time
import codecs

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("Please install the 'cryptography' module (pip install cryptography) for encryption features.")
    exit(1)


class AdvancedPasswordGenerator:
    def __init__(self, password_length=16):
        self.password_length = password_length
        self.salt = os.urandom(16)
        self.generated_password = self.generate_random_password()

    # Feature 1: Generate a base random password
    def generate_random_password(self):
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(characters) for _ in range(self.password_length))

    # Feature 2: Check password strength based on basic rules
    def feature2_check_strength(self, password):
        strength = 0
        if len(password) >= self.password_length:
            strength += 20
        if any(c.islower() for c in password):
            strength += 20
        if any(c.isupper() for c in password):
            strength += 20
        if any(c.isdigit() for c in password):
            strength += 20
        if any(c in string.punctuation for c in password):
            strength += 20
        return strength

    # Feature 3: Hash the password using SHA-256
    def feature3_hash_password(self, password):
        hash_obj = hashlib.sha256(password.encode())
        return hash_obj.hexdigest()

    # Feature 4: Encrypt the password using AES in CFB mode
    def feature4_encrypt_password(self, password):
        key = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(password.encode()) + encryptor.finalize()
        return {
            'key': base64.b64encode(key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }

    # Feature 5: Compute the Shannon entropy of the password
    def feature5_compute_entropy(self, password):
        prob = {}
        for char in password:
            prob[char] = password.count(char) / len(password)
        entropy = -sum(p * math.log2(p) for p in prob.values())
        return entropy

    # Feature 6: Simulate breach detection by checking common weak passwords
    def feature6_breach_detection(self, password):
        common_passwords = ['password', '123456', 'admin', 'qwerty']
        return password.lower() in common_passwords

    # Feature 7: Generate a pseudo TOTP code (dummy implementation)
    def feature7_generate_totp(self):
        return str(random.randint(100000, 999999))

    # Feature 8: Log the password generation event with timestamp
    def feature8_log_event(self, event):
        timestamp = datetime.datetime.now().isoformat()
        log_entry = f"{timestamp}: {event}"
        return log_entry

    # Feature 9: Simulate a multi-layer password string modification (reverse then swap case)
    def feature9_modify_password_layers(self, password):
        modified = password[::-1]  # Reverse
        modified = modified.swapcase()  # Swap case
        return modified

    # Feature 10: Add a random special character into the password at a random position
    def feature10_add_special_chars(self, password):
        special_chars = "!@#$%^&*()-_=+[]{};:,.<>/?"
        insert_idx = random.randint(0, len(password))
        return password[:insert_idx] + random.choice(special_chars) + password[insert_idx:]

    # Feature 11: Extend password with a timestamp hash (using MD5 for demonstration)
    def feature11_timestamp_hash(self, password):
        timestamp = str(time.time())
        combined = password + timestamp
        return hashlib.md5(combined.encode()).hexdigest()

    # Feature 12: Base64 encode the password for transmission
    def feature12_base64_encode(self, password):
        return base64.b64encode(password.encode()).decode('utf-8')

    # Feature 13: Generate a double salted hash of the password (using SHA-256)
    def feature13_double_salt_hash(self, password):
        salt2 = os.urandom(16)
        combined = password + base64.b64encode(salt2).decode('utf-8')
        return hashlib.sha256(combined.encode()).hexdigest()

    # Feature 14: Simulate an SQL injection test by checking for common injection strings
    def feature14_sql_injection_test(self, password):
        injection_signatures = ["' OR '1'='1", "'; DROP TABLE", "\" OR \"\" = \""]
        return any(inj in password for inj in injection_signatures)

    # Feature 15: Check for dictionary words in the password (dummy check)
    def feature15_dictionary_check(self, password):
        dictionary_words = ['hello', 'password', 'letmein']
        for word in dictionary_words:
            if word in password.lower():
                return True
        return False

    # Feature 16: Simulate a buffer overflow check (dummy: flag if password is very long)
    def feature16_buffer_overflow_check(self, password):
        return len(password) > 100

    # Feature 17: Replace characters using leetspeak conversion
    def feature17_leetspeak_conversion(self, password):
        leet_dict = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
        return ''.join(leet_dict.get(c.lower(), c) for c in password)

    # Feature 18: Introduce a random delay to mimic complex processing
    def feature18_random_delay(self):
        delay = random.uniform(0.1, 0.5)
        time.sleep(delay)
        return delay

    # Feature 19: Generate a complex key using PBKDF2 with the password and salt
    def feature19_pbkdf2_key(self, password):
        iterations = 100000
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), self.salt, iterations)
        return base64.b64encode(key).decode('utf-8')

    # Feature 20: Check for repeating sequences in the password
    def feature20_repeating_sequences_check(self, password):
        for i in range(1, len(password) // 2):
            if password.count(password[:i]) > 1:
                return True
        return False

    # Feature 21: Improve entropy by appending additional random punctuation
    def feature21_improve_entropy(self, password):
        extra_chars = ''.join(secrets.choice(string.punctuation) for _ in range(4))
        return password + extra_chars

    # Feature 22: Generate a hacker‑style tagline
    def feature22_generate_tagline(self):
        taglines = [
            "Access Granted",
            "Override Complete",
            "System Breached",
            "Encryption Enabled",
            "Hack the Planet!"
        ]
        return random.choice(taglines)

    # Feature 23: Simulate network latency measurement (dummy value in ms)
    def feature23_network_latency_simulation(self):
        return random.randint(50, 150)

    # Feature 24: Log detailed debug message (dummy implementation)
    def feature24_debug_log(self, message):
        return f"DEBUG: {message}"

    # Feature 25: Compare against a list of leaked passwords (dummy list)
    def feature25_leaked_password_check(self, password):
        leaked_passwords = ["123456", "password", "123456789", "qwerty"]
        return password in leaked_passwords

    # Feature 26: Convert password to its hexadecimal representation
    def feature26_hex_conversion(self, password):
        return password.encode().hex()

    # Feature 27: Generate a new random salt for additional security
    def feature27_generate_salt(self):
        return base64.b64encode(os.urandom(16)).decode('utf-8')

    # Feature 28: XOR each character with a random key (dummy obfuscation)
    def feature28_xor_obfuscation(self, password):
        key = random.randint(1, 255)
        obfuscated = ''.join(chr(ord(c) ^ key) for c in password)
        return obfuscated, key

    # Feature 29: Reverse the password string as an obfuscation layer
    def feature29_reverse_string(self, password):
        return password[::-1]

    # Feature 30: Mix two password variations together
    def feature30_mix_passwords(self, password1, password2):
        mixed = ''.join(a + b for a, b in zip(password1, password2))
        return mixed

    # Feature 31: Append a random numeric sequence to the password
    def feature31_add_numeric_sequence(self, password):
        num_seq = ''.join(str(random.randint(0, 9)) for _ in range(4))
        return password + num_seq

    # Feature 32: Shift each character’s ASCII value by a random amount (modulo 128)
    def feature32_ascii_shift(self, password):
        shift = random.randint(1, 10)
        shifted = ''.join(chr((ord(c) + shift) % 128) for c in password)
        return shifted, shift

    # Feature 33: Create a visual ASCII art representation of the password
    def feature33_ascii_art(self, password):
        art = f"""
+-------------------------------+
|  Password: {password}  |
+-------------------------------+
"""
        return art

    # Feature 34: Simulate secure deletion of password data (dummy function)
    def feature34_secure_delete(self):
        return "Secure deletion simulated: memory cleared."

    # Feature 35: Produce an HMAC for the integrity of the password
    def feature35_hmac_integrity(self, password):
        key = os.urandom(16)
        hmac_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), key, 1000)
        return base64.b64encode(hmac_obj).decode('utf-8')

    # Feature 36: Validate the password against custom security policies
    def feature36_custom_policy_validation(self, password):
        if len(password) < self.password_length:
            return False, "Password too short"
        if not any(c.isupper() for c in password):
            return False, "Missing uppercase letter"
        if not any(c.isdigit() for c in password):
            return False, "Missing digit"
        return True, "Password meets custom policy"

    # Feature 37: Simulate a firewall scan for suspicious patterns (dummy)
    def feature37_firewall_scan(self, password):
        if "firewall" in password.lower():
            return "Alert: 'firewall' pattern detected!"
        return "No issues detected"

    # Feature 38: Apply a Caesar cipher to the password
    def feature38_caesar_cipher(self, password, shift=3):
        result = ''
        for c in password:
            if c.isalpha():
                base = 'a' if c.islower() else 'A'
                result += chr((ord(c) - ord(base) + shift) % 26 + ord(base))
            else:
                result += c
        return result

    # Feature 39: Convert the password into a binary string sequence
    def feature39_binary_conversion(self, password):
        return ' '.join(format(ord(c), '08b') for c in password)

    # Feature 40: Calculate a simple checksum for the password
    def feature40_checksum(self, password):
        return sum(ord(c) for c in password) % 256

    # Feature 41: Simulate a delay representing user input (for realism)
    def feature41_user_input_delay(self):
        delay = random.uniform(0.5, 2.0)
        time.sleep(delay)
        return delay

    # Feature 42: Generate a hacker‑style log message
    def feature42_hacker_log(self, message):
        return f"[HACKER LOG] {message}"

    # Feature 43: Randomly scramble the characters of the password
    def feature43_scramble_characters(self, password):
        password_list = list(password)
        random.shuffle(password_list)
        return ''.join(password_list)

    # Feature 44: Create a mirror image string of the password
    def feature44_mirror_string(self, password):
        return password + password[::-1]

    # Feature 45: Append the current system time to the password for entropy
    def feature45_append_system_time(self, password):
        system_time = str(time.time())
        return password + system_time

    # Feature 46: Apply ROT13 transformation to the password
    def feature46_rot13_transformation(self, password):
        return codecs.encode(password, 'rot_13')

    # Feature 47: Simulate a code obfuscation routine (randomly alter case)
    def feature47_code_obfuscation(self, password):
        return ''.join(random.choice([c.upper(), c.lower()]) for c in password)

    # Feature 48: Generate a dummy digital signature for the password
    def feature48_digital_signature(self, password):
        signature = hashlib.sha1((password + "secret").encode()).hexdigest()
        return signature

    # Feature 49: Simulate multi-threaded processing (dummy delay)
    def feature49_multithread_simulation(self, password):
        time.sleep(0.1)
        return "Simulated multi-threading complete"

    # Feature 50: Log all feature execution securely to a file
    def feature50_secure_logging(self, log_message):
        log_file = "secure_log.txt"
        with open(log_file, "a") as f:
            f.write(log_message + "\n")
        return f"Message logged to {log_file}"

    # Run all features sequentially and return a dictionary of results
    def run_all_features(self):
        results = {}
        results['base_password'] = self.generated_password
        results['strength'] = self.feature2_check_strength(self.generated_password)
        results['sha256_hash'] = self.feature3_hash_password(self.generated_password)
        results['encrypted'] = self.feature4_encrypt_password(self.generated_password)
        results['entropy'] = self.feature5_compute_entropy(self.generated_password)
        results['breach_detected'] = self.feature6_breach_detection(self.generated_password)
        results['totp'] = self.feature7_generate_totp()
        results['log_event'] = self.feature8_log_event("Password generated")
        results['modified_layers'] = self.feature9_modify_password_layers(self.generated_password)
        results['special_char_added'] = self.feature10_add_special_chars(self.generated_password)
        results['timestamp_hash'] = self.feature11_timestamp_hash(self.generated_password)
        results['base64_encoded'] = self.feature12_base64_encode(self.generated_password)
        results['double_salt_hash'] = self.feature13_double_salt_hash(self.generated_password)
        results['sql_injection'] = self.feature14_sql_injection_test(self.generated_password)
        results['dictionary_check'] = self.feature15_dictionary_check(self.generated_password)
        results['buffer_overflow'] = self.feature16_buffer_overflow_check(self.generated_password)
        results['leetspeak'] = self.feature17_leetspeak_conversion(self.generated_password)
        results['random_delay'] = self.feature18_random_delay()
        results['pbkdf2_key'] = self.feature19_pbkdf2_key(self.generated_password)
        results['repeating_sequences'] = self.feature20_repeating_sequences_check(self.generated_password)
        results['improve_entropy'] = self.feature21_improve_entropy(self.generated_password)
        results['tagline'] = self.feature22_generate_tagline()
        results['network_latency'] = self.feature23_network_latency_simulation()
        results['debug_log'] = self.feature24_debug_log("All systems nominal")
        results['leaked_check'] = self.feature25_leaked_password_check(self.generated_password)
        results['hex_conversion'] = self.feature26_hex_conversion(self.generated_password)
        results['new_salt'] = self.feature27_generate_salt()
        obfuscation, xor_key = self.feature28_xor_obfuscation(self.generated_password)
        results['xor_obfuscation'] = obfuscation
        results['xor_key'] = xor_key
        results['reverse_string'] = self.feature29_reverse_string(self.generated_password)
        results['mixed_passwords'] = self.feature30_mix_passwords(self.generated_password, self.feature29_reverse_string(self.generated_password))
        results['numeric_sequence'] = self.feature31_add_numeric_sequence(self.generated_password)
        ascii_shifted, shift_val = self.feature32_ascii_shift(self.generated_password)
        results['ascii_shifted'] = ascii_shifted
        results['shift_value'] = shift_val
        results['ascii_art'] = self.feature33_ascii_art(self.generated_password)
        results['secure_delete'] = self.feature34_secure_delete()
        results['hmac_integrity'] = self.feature35_hmac_integrity(self.generated_password)
        policy_valid, policy_message = self.feature36_custom_policy_validation(self.generated_password)
        results['custom_policy'] = policy_message
        results['firewall'] = self.feature37_firewall_scan(self.generated_password)
        results['caesar_cipher'] = self.feature38_caesar_cipher(self.generated_password)
        results['binary_conversion'] = self.feature39_binary_conversion(self.generated_password)
        results['checksum'] = self.feature40_checksum(self.generated_password)
        results['input_delay'] = self.feature41_user_input_delay()
        results['hacker_log'] = self.feature42_hacker_log("Password generation complete")
        results['scrambled'] = self.feature43_scramble_characters(self.generated_password)
        results['mirror_string'] = self.feature44_mirror_string(self.generated_password)
        results['append_time'] = self.feature45_append_system_time(self.generated_password)
        results['rot13'] = self.feature46_rot13_transformation(self.generated_password)
        results['code_obfuscation'] = self.feature47_code_obfuscation(self.generated_password)
        results['digital_signature'] = self.feature48_digital_signature(self.generated_password)
        results['multithread'] = self.feature49_multithread_simulation(self.generated_password)
        results['secure_logging'] = self.feature50_secure_logging("Executed all 50 features.")
        return results


if __name__ == "__main__":
    generator = AdvancedPasswordGenerator(password_length=16)
    results = generator.run_all_features()
    for feature, output in results.items():
        print(f"{feature} : {output}\n")
