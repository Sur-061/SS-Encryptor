import tkinter as tk
from tkinter import filedialog, messagebox
import os
import time

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def create_key(password, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,         
        n=2**14,
        r=8,
        p=1
    )

    return kdf.derive(password.encode("utf-8"))


def choose_file():
    file_path = filedialog.askopenfilename()

    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)


def encrypt_file():

    file_path = file_entry.get()
    password = password_entry.get()

    if not file_path:
        messagebox.showwarning(
            "Զգուշացում",
            "Ընտրեք ֆայլը։"
        )
        return

    if not password:
        messagebox.showwarning(
            "Զգուշացում",
            "Մուտքագրեք գաղտնաբառը։"
        )
        return

    try:

        start_time = time.perf_counter()

        with open(file_path, "rb") as file:
            data = file.read()

        salt = os.urandom(16)

        key = create_key(password, salt)

        aes = AESGCM(key)

        nonce = os.urandom(12)

        encrypted_data = aes.encrypt(
            nonce,
            data,
            None
        )

        
        output_file = file_path + ".enc"

        with open(output_file, "wb") as file:
            file.write(salt)
            file.write(nonce)
            file.write(encrypted_data)

        end_time = time.perf_counter()

        elapsed = end_time - start_time

        messagebox.showinfo(
            "Հաջողություն",
            f"Ֆայլը հաջողությամբ գաղտնագրվել է։\n\n"
            f"Ստեղծված ֆայլը՝\n{output_file}\n\n"
            f"Կատարման ժամանակը՝ {elapsed:.4f} վրկ"
        )

    except Exception as error:

        messagebox.showerror(
            "Սխալ",
            f"Գաղտնագրման ժամանակ առաջացավ սխալ։\n\n{error}"
        )


def decrypt_file():

    file_path = file_entry.get()
    password = password_entry.get()

    if not file_path:
        messagebox.showwarning(
            "Զգուշացում",
            "Ընտրեք գաղտնագրված ֆայլը։"
        )
        return

    if not password:
        messagebox.showwarning(
            "Զգուշացում",
            "Մուտքագրեք գաղտնաբառը։"
        )
        return

    try:

        start_time = time.perf_counter()

        with open(file_path, "rb") as file:
            encrypted_file = file.read()

        if len(encrypted_file) < 29:
            raise ValueError(
                "Ֆայլը չի հանդիսանում ճիշտ գաղտնագրված ֆայլ։"
            )

        salt = encrypted_file[:16]

        nonce = encrypted_file[16:28]

        encrypted_data = encrypted_file[28:]

        key = create_key(password, salt)

        aes = AESGCM(key)

        decrypted_data = aes.decrypt(
            nonce,
            encrypted_data,
            None
        )

        if file_path.endswith(".enc"):
            output_file = file_path[:-4]
        else:
            output_file = file_path + ".decrypted"

        with open(output_file, "wb") as file:
            file.write(decrypted_data)

        end_time = time.perf_counter()

        elapsed = end_time - start_time

        messagebox.showinfo(
            "Հաջողություն",
            f"Ֆայլը հաջողությամբ գաղտնազերծվել է\n\n"
            f"Վերականգնված ֆայլը՝\n{output_file}\n\n"
            f"Կատարման ժամանակը՝ {elapsed:.4f} վրկ"
        )

    except Exception:

        messagebox.showerror(
        "Սխալ",
        "Գաղտնազերծումը հնարավոր չէ։\n\n"
        "Ստուգեք գաղտնաբառը կամ համոզվեք, "
        "որ ֆայլը չի փոփոխվել։"
    )

window = tk.Tk()

window.title("SS Encryptor")
window.geometry("800x400")
window.resizable(True, True)

title_label = tk.Label(
    window,
    text="SS Encryptor",
    font=("Calibri", 20, "bold")
)

title_label.pack(pady=20)

file_frame = tk.Frame(window)
file_frame.pack(pady=10)


tk.Label(
    file_frame,
    text="Ֆայլ:",
    font=("Calibri", 11)
).pack(side=tk.LEFT, padx=5)


file_entry = tk.Entry(
    file_frame,
    width=45
)

file_entry.pack(side=tk.LEFT, padx=5)


tk.Button(
    file_frame,
    text="Ընտրել ֆայլը",
    command=choose_file
).pack(side=tk.LEFT)

password_frame = tk.Frame(window)
password_frame.pack(pady=15)


tk.Label(
    password_frame,
    text="Գաղտնաբառ:",
    font=("Calibri", 11)
).pack(side=tk.LEFT, padx=5)


password_entry = tk.Entry(
    password_frame,
    width=30,
    show="*"
)

password_entry.pack(side=tk.LEFT, padx=5)

button_frame = tk.Frame(window)
button_frame.pack(pady=20)


tk.Button(
    button_frame,
    text="Գաղտնագրել",
    width=18,
    height=2,
    command=encrypt_file
).pack(side=tk.LEFT, padx=10)


tk.Button(
    button_frame,
    text="Գաղտնազերծել",
    width=18,
    height=2,
    command=decrypt_file
).pack(side=tk.LEFT, padx=10)

window.mainloop()