import tkinter as tk
from tkinter import messagebox


def substitution_cipher(message, key, decrypt=False):
    result = ""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key = key.upper()

    for char in message:
        if char in alphabet:
            index = (alphabet.index(char) - alphabet.index(key[0])) if decrypt else (
                        alphabet.index(char) + alphabet.index(key[0]))
            index = index % 26  # Ensure it stays within the range of the alphabet
            result += alphabet[index]
        else:
            result += char

    return result


def brute_force_decrypt(ciphertext):
    acceptable_keys = []
    decrypted_messages = []

    for possible_key in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        decrypted_message = substitution_cipher(ciphertext, possible_key, decrypt=True)

        if is_acceptable_decryption(decrypted_message):
            acceptable_keys.append(possible_key)
            decrypted_messages.append(decrypted_message)

    return acceptable_keys, decrypted_messages


def is_acceptable_decryption(decrypted_message):
    # You might want to customize this function based on characteristics of the decrypted message
    # For example, check if the decrypted message contains common English words or phrases
    common_words = ["THE", "AND", "IS", "OF"]
    for word in common_words:
        if word in decrypted_message:
            return True
    return False


class BruteForceCipherGUI:
    def __init__(self, master):
        self.master = master
        master.title("Brute Force Substitution Cipher GUI")

        # Create widgets
        self.label_message = tk.Label(master, text="Enter Encrypted Message:")
        self.entry_message = tk.Entry(master)
        self.decrypt_button = tk.Button(master, text="Brute Force Decrypt", command=self.brute_force_decrypt)

        # Result text box
        self.result_text = tk.Text(master, height=10, width=40)
        self.result_text.insert(tk.END, "Acceptable Decryptions:\n")
        self.result_text.config(state=tk.DISABLED)  # Disable editing

        # Arrange widgets
        self.label_message.grid(row=0, column=0, sticky=tk.E)
        self.entry_message.grid(row=0, column=1, padx=10, pady=10)
        self.decrypt_button.grid(row=1, column=0, columnspan=2, pady=10)
        self.result_text.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    def brute_force_decrypt(self):
        ciphertext = self.entry_message.get().upper()
        self.result_text.config(state=tk.NORMAL)  # Enable editing
        self.result_text.delete(2.0, tk.END)  # Clear previous results
        self.result_text.insert(tk.END, "Acceptable Decryptions:\n")
        self.result_text.config(state=tk.DISABLED)  # Disable editing

        acceptable_keys, decrypted_messages = brute_force_decrypt(ciphertext)

        if not acceptable_keys:
            messagebox.showinfo("No Acceptable Decryptions", "No acceptable decryptions found.")
        else:
            for key, message in zip(acceptable_keys, decrypted_messages):
                self.result_text.config(state=tk.NORMAL)  # Enable editing
                self.result_text.insert(tk.END, f"Key '{key}': {message}\n")
                self.result_text.config(state=tk.DISABLED)  # Disable editing


def main():
    root = tk.Tk()
    app = BruteForceCipherGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()