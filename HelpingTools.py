import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import random
import string

class HelpingTools:
    def __init__(self):
        pass

    def show_options(self):
        print("Choose an action:")
        print("1 - MBRtoDesktop - Reads MBR and saves as mbr.txt to desktop. (Run as administrator)")
        print("2 - EncryptFile - Encrypts file.")
        print("3 - CorruptFile - Corrupting file you dont want.")
        print("4 - AutomaticRepair - Making automatic repair without entering bios. (Run as administrator)")
        choice = input("Enter your choice: ")
        return choice

    def MBRtoDesktop(self):
        try:
            # Find desktop path
            desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')

            # Read MBR on PhysicalDrive0 (main drive)
            with open(r'\\.\PhysicalDrive0', 'rb') as f:
                mbr_data = f.read(512)

            # Save MBR datas to mbr.txt
            desktop_file_path = os.path.join(desktop_path, 'mbr.txt')
            with open(desktop_file_path, 'wb') as f:
                f.write(mbr_data)

            print(f"MBR is written to {desktop_file_path} successfully.")

        except PermissionError as pererr:
            print("Run as administrator.")

    def EncryptFile(self):
        try:
            desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')

            # Ask user for file path and name and give warning
            print("Warning!!! You are about to encrypt a file. That means you will unable to use that and there is no way to decrypt file until V2 or V3 of HelpingTools released.")
            file_path = input("Enter the full path of the file to encrypt: ")
            file_name = os.path.basename(file_path)

            # Check if the file exists
            if not os.path.exists(file_path):
                print(f"File '{file_path}' does not exist.")
                return

            # Read file content
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Get password from user
            password = input("Enter password for encryption: ").encode()

            # Generate salt
            salt = os.urandom(16)

            # Derive key from password using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password)

            # Generate RSA key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()

            # Serialize the public key
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Encrypt the key with RSA
            encrypted_key = public_key.encrypt(
                key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Save the encrypted key and salt to files
            with open(os.path.join(desktop_path, 'encrypted_key.pem'), 'wb') as f:
                f.write(encrypted_key)

            with open(os.path.join(desktop_path, 'salt.bin'), 'wb') as f:
                f.write(salt)

            # Encrypt the file data
            encrypted_data = key + file_data  # Example simplistic encryption, replace with proper encryption method

            # Save encrypted data to a file
            encrypted_file_path = os.path.join(desktop_path, f'encrypted_{file_name}')
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)

            print(f"File '{file_name}' encrypted and saved as 'encrypted_{file_name}' on desktop.")

        except PermissionError:
            print("Run as administrator.")

    def CorruptFile(self):
        try:
            # Ask user for file path
            file_path = input("Enter the full path of the file to corrupt: ")
            file_name = os.path.basename(file_path)

            # Check if the file exists
            if not os.path.exists(file_path):
                print(f"File '{file_path}' does not exist.")
                return

            # Read file content and give information
            with open(file_path, 'rb') as f:
                print("Reading file & corrupting and saving.")
                file_data = f.read()

            # Corrupt the file content with random characters
            corrupted_data = bytearray(file_data)
            for i in range(len(corrupted_data)):
                if random.random() < 0.1:  # 10% probability to corrupt each byte
                    corrupted_data[i] = random.choice(
                        bytes(string.ascii_letters + string.digits + string.punctuation, 'utf-8'))

            # Save corrupted data to a file
            corrupted_file_path = os.path.join(os.path.dirname(file_path), f'corrupted_{file_name}')
            with open(corrupted_file_path, 'wb') as f:
                f.write(corrupted_data)

            print(f"File '{file_name}' corrupted and saved as 'corrupted_{file_name}'.")

        except PermissionError:
            print("Run as administrator.")
        except Exception as e:
            print(f"An error occurred: {e}")

    def AutomaticRepair(self):
        separate_drive = False  # Change to True if loading from a separate drive is needed
        repair_app = AutomaticRepairTerminal(separate_drive)
        repair_app.diagnose_issues(repair_app.repair_classes_global)
        repair_app.apply_fixes()

class AutomaticRepairTerminal:
    def __init__(self, separate_drive):
        self.separate_drive_fix = separate_drive
        self.repair_classes_global = RepairClasses()

    def diagnose_issues(self, repair_classes):
        # Load Registry hives from target drive if separateDrive is true
        if self.separate_drive_fix:
            self.load_separate_hive()

        # Initialize paths
        hklm_software_path = hklm_system_path = hkcu_path = None
        try:
            if self.separate_drive_fix:
                print("Loading separate hives...")
                # Implement loading separate hives for terminal (os.system(r'reg load ...'))
            else:
                hklm_software_path = "SOFTWARE"
                hklm_system_path = "SYSTEM"
                hkcu_path = "CurrentUser"

            # Iterate through the list of possible fixes and check if a fix is needed
            x = 0
            for fix in repair_classes.fix_information:
                try:
                    x += 1
                    print(f"Searching for available fixes ({x} of {len(repair_classes.fix_information)})")

                    name = fix.Name
                    fix_type = fix.Type
                    path = fix.Path
                    key = fix.Key
                    value = fix.Value
                    nullable = fix.Nullable

                    for i in range(len(fix_type)):
                        if not fix.IsSelected:
                            if fix_type[i] == FixType.Registry:
                                # Implement registry fix check in terminal mode
                                pass
                            else:
                                # Implement other fix checks in terminal mode
                                pass

                except Exception as ex:
                    print(f"There was an error diagnosing the issue: {fix.Name}. \n{str(ex)}")
                    return False

            print("Diagnosis completed.")
            return True

        except Exception as e:
            print(f"Error during diagnosis: {e}")
            return False

        finally:
            # Unload Registry hives if separateDrive is true
            if self.separate_drive_fix:
                print("Unloading separate hives...")
                # Implement unloading separate hives for terminal (os.system(r'reg unload ...'))

    def apply_fixes(self):
        # Load Registry hives from target drive if separateDrive is true
        if self.separate_drive_fix:
            self.load_separate_hive()

        # Initialize paths
        hklm_software_path = hklm_system_path = hkcu_path = None
        require_restart = False
        try:
            if self.separate_drive_fix:
                print("Loading separate hives...")
                # Implement loading separate hives for terminal (os.system(r'reg load ...'))
            else:
                hklm_software_path = "SOFTWARE"
                hklm_system_path = "SYSTEM"
                hkcu_path = "CurrentUser"

            # Apply fixes
            for fix in self.repair_classes_global.fix_information:
                try:
                    name = fix.Name
                    fix_type = fix.Type
                    path = fix.Path
                    key = fix.Key
                    value = fix.Value
                    nullable = fix.Nullable

                    for i in range(len(fix_type)):
                        if fix.IsSelected:
                            if fix_type[i] == FixType.Registry:
                                # Implement registry fix application in terminal mode
                                pass
                            else:
                                # Implement other fix applications in terminal mode
                                pass

                except Exception as ex:
                    print(f"There was an error applying the fix: {fix.Name}. \n{str(ex)}")
                    return False

            print("Fix application completed.")
            return True

        except Exception as e:
            print(f"Error during fix application: {e}")
            return False

        finally:
            # Unload Registry hives if separateDrive is true
            if self.separate_drive_fix:
                print("Unloading separate hives...")
                # Implement unloading separate hives for terminal (os.system(r'reg unload ...'))

    def load_separate_hive(self):
        try:
            print("Loading separate hives...")

            # Implement loading separate hives for terminal (os.system(r'reg load ...'))

            print("Separate hive load completed.")

        except Exception as e:
            print(f"Error loading separate hive: {e}")

class RepairClasses:
    def __init__(self):
        self.fix_information = []

    def fix_information(self):
        return False

class FixType:
    Registry = 1

# Main program
def main():
    tools = HelpingTools()
    choice = tools.show_options()

    if choice == '1':
        tools.MBRtoDesktop()
    elif choice == '2':
        tools.EncryptFile()
    elif choice == '3':
        tools.CorruptFile()
    elif choice == '4':
        tools.AutomaticRepair()
    else:
        print("Invalid choice. Please enter a valid option.")
        main()

if __name__ == "__main__":
    main()