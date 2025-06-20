import tkinter as tk
from tkinter.ttk import Label, Entry, Button
from PIL import Image, ImageTk

def encrypt(text, key):
    result = ""
    key_index = 0
    key = key.lower()

    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)])- ord('a')
            if char.islower():
                encrypted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            result += encrypted_char
            key_index += 1
        else:
            result += char  # Boşluk, sayı, noktalama olduğu gibi kalır
    return result

def decrypt_and_display():
    master_key = masterkey_entry.get()

    if not master_key:
        print("Lütfen şifrenizi girin.")
        return

    try:
        with open("mysecret.txt", "r") as file:
            lines = file.readlines()
            if len(lines) < 2:
                print("Dosyada yeterli bilgi yok dost.")
                return

            title = lines[0].strip()
            encrypted_text = lines[1].strip()

            decrypted_text = decrypt(encrypted_text, master_key)
            if decrypted_text.startswith("SECRETMSG::"):
                real_secret = decrypted_text.replace("SECRETMSG::", "", 1)

                name_entry.delete(0, tk.END)
                name_entry.insert(0, title)

                secret_textbox.delete("1.0", tk.END)
                secret_textbox.insert(tk.END, real_secret)

                print("Not başarıyla çözüldü.")
            else:
                print("Hatalı şifre girildi.")
    except FileNotFoundError:
        print("Şifreli dosya bulunamadı.")

def save_and_encrypt():
    title = name_entry.get()
    secret = secret_textbox.get("1.0", tk.END).strip()
    master_key = masterkey_entry.get()

    if not title or not secret or not master_key:
        print("Lütfen tüm alanları doldurun.")
        return

    combined = f"SECRETMSG::{secret}"
    encrypted_text = encrypt(combined, master_key)

    with open("mysecret.txt", "w") as file:
        file.write(f"{title}\n{encrypted_text}")

    secret_textbox.delete("1.0", tk.END)
    masterkey_entry.delete(0, tk.END)
    name_entry.delete(0, tk.END)
    print("Şifreli not kaydedildi.")

def decrypt(text, key):
    result = ""
    key_index = 0
    key = key.lower()

    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            if char.islower():
                decrypted_char = chr((ord(char) - ord('a')- shift) % 26 + ord('a'))
            else:
                decrypted_char = chr((ord(char)- ord('A') - shift) % 26 + ord('A'))
            result += decrypted_char
            key_index += 1
        else:
            result += char
    return  result


window = tk.Tk()
window.title("Secret Notes")
window.minsize(width=400, height=600)
window.config(padx=20, pady=20)

original_image = Image.open("topsecret.png")
resized_image = original_image.resize((100, 100))
image = ImageTk.PhotoImage(resized_image)

image_label = tk.Label(window, image=image)
image_label.image = image
image_label.pack()

name_label = Label(text="Enter your title")
name_label.pack()

name_entry = Entry(width=20)
name_entry.pack()

secret_label = Label(text="Enter your secret")
secret_label.pack()

secret_textbox = tk.Text(window, width=35, height=18)
secret_textbox.pack()


masterkey_label = Label(text="Enter master key")
masterkey_label.pack()

masterkey_entry = Entry(width=25)
masterkey_entry.pack()

check_button_1 = Button(text="Save & Encrypt", command=save_and_encrypt)
check_button_1.pack()

check_button_2 = Button(text="Decrypt", command=decrypt_and_display)
check_button_2.pack()


window.mainloop()

