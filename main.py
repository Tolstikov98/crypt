import tkinter as tk
from tkinter import messagebox, filedialog
from collections import Counter, defaultdict
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import importlib.util

translations = {
    'en': {
        'title': "Ciphers",
        'language_label': "Select language:",
        'interface_language_label': "Interface language:",
        'cipher_label': "Ciphers:",
        'vigenere_cipher_label': "Vigenere Cipher",
        'caesar_cipher_label': "Caesar Cipher",
        'text_label': "Enter text:",
        'load_button': "Load text from file",
        'key_label': "Enter key:",
        'action_encrypt': "Encrypt",
        'action_decrypt': "Decrypt",
        'process_button': "Execute",
        'result_label': "Result:",
        'save_button': "Save result to file",
        'frequency_analysis': "Frequency Analysis",
        'guess_key': "Guess Key",
        'error_empty_text': "Text and key cannot be empty!",
        'error_invalid_language': "Unsupported language!",
        'error_invalid_key': "Invalid key!"
    },
    'ru': {
        'title': "Шифры",
        'language_label': "Выберите язык:",
        'interface_language_label': "Язык интерфейса:",
        'cipher_label': "Шифры:",
        'vigenere_cipher_label': "Шифр Вижнера",
        'caesar_cipher_label': "Шифр Цезаря",
        'text_label': "Введите текст:",
        'load_button': "Загрузить текст из файла",
        'key_label': "Введите ключ:",
        'action_encrypt': "Шифрование",
        'action_decrypt': "Дешифрование",
        'process_button': "Выполнить",
        'result_label': "Результат:",
        'save_button': "Сохранить результат в файл",
        'frequency_analysis': "Частотный анализ",
        'guess_key': "Угадать ключ",
        'error_empty_text': "Текст и ключ не должны быть пустыми!",
        'error_invalid_language': "Неподдерживаемый язык!",
        'error_invalid_key': "Неправильный ключ!"
    }
}

def translate_interface(lang):
    root.title(translations[lang]['title'])
    language_label.config(text=translations[lang]['language_label'])
    interface_language_label.config(text=translations[lang]['interface_language_label'])
    cipher_label.config(text=translations[lang]['cipher_label'])
    text_label.config(text=translations[lang]['text_label'])
    load_button.config(text=translations[lang]['load_button'])
    key_label.config(text=translations[lang]['key_label'])
    vigenere_radio.config(text=translations[lang]['vigenere_cipher_label'])
    caesar_radio.config(text=translations[lang]['caesar_cipher_label'])
    encrypt_radio.config(text=translations[lang]['action_encrypt'])
    decrypt_radio.config(text=translations[lang]['action_decrypt'])
    process_button.config(text=translations[lang]['process_button'])
    result_label.config(text=translations[lang]['result_label'])
    save_button.config(text=translations[lang]['save_button'])
    frequency_button.config(text=translations[lang]['frequency_analysis'])
    guess_key_button.config(text=translations[lang]['guess_key'])

def configure_text_widget(widget, font_name="Arial", font_size=12, bg_color="white", fg_color="black"):
    widget.config(font=(font_name, font_size), bg=bg_color, fg=fg_color)

def kasiski_examination(ciphertext, min_length=3):
    def find_repeats(text, min_length):
        repeats = defaultdict(list)
        for length in range(min_length, len(text) // 2 + 1):
            for i in range(len(text) - length):
                segment = text[i:i + length]
                if segment in text[i + length:]:
                    repeats[segment].append(i)
        return repeats

    repeats = find_repeats(ciphertext, min_length)
    distances = []

    for positions in repeats.values():
        for i in range(1, len(positions)):
            distance = positions[i] - positions[i - 1]
            distances.append(distance)

    gcd = lambda a, b: b if a == 0 else gcd(b % a, a)

    def find_gcd_list(num_list):
        num_list = list(num_list)
        if len(num_list) == 0:
            return 0
        x = num_list[0]
        for i in num_list[1:]:
            x = gcd(x, i)
        return x

    probable_key_length = find_gcd_list(distances)
    return probable_key_length

def guess_key_based_on_frequency(ciphertext, alphabet):
    freqs = Counter(ciphertext)
    most_common_char = freqs.most_common(1)[0][0]

    if alphabet == get_extended_alphabet('EN'):
        likely_char = 'E'
    elif alphabet == get_extended_alphabet('RU'):
        likely_char = 'О'
    else:
        raise ValueError("Неподдерживаемый язык")

    guessed_shift = (alphabet.index(most_common_char.upper()) - alphabet.index(likely_char)) % len(alphabet)
    guessed_key = alphabet[guessed_shift]

    print(f"Предполагаемый ключ: {guessed_key}")
    return guessed_key

def frequency_analysis(ciphertext, alphabet):

    freqs = Counter(ciphertext)

    print("Частотный анализ:")
    for char, freq in freqs.most_common():
        if char.upper() in alphabet:
            print(f"{char}: {freq}")

def frequency_analysis_gui():
    text = text_entry.get("1.0", tk.END).strip()
    language = language_var.get()

    if not text:
        messagebox.showerror("Ошибка", "Текст не должен быть пустым!")
        return

    try:
        alphabet = get_extended_alphabet(language)
    except ValueError as e:
        messagebox.showerror("Ошибка", str(e))
        return

    frequency_analysis(text, alphabet)

def guess_key_gui():
    """Попытка угадать ключ на основе частотного анализа из GUI."""
    text = text_entry.get("1.0", tk.END).strip()
    language = language_var.get()

    if not text:
        messagebox.showerror("Ошибка", "Текст не должен быть пустым!")
        return

    try:
        alphabet = get_extended_alphabet(language)
    except ValueError as e:
        messagebox.showerror("Ошибка", str(e))
        return

    guessed_key = guess_key_based_on_frequency(text, alphabet)
    result = vigenere_decrypt(text, guessed_key, alphabet)

    result_entry.delete("1.0", tk.END)
    result_entry.insert(tk.END, f"Предполагаемый ключ: {guessed_key}\nРезультат:\n{result}")

def adjust_key_length(key, length):
    key = key.upper()
    return (key * (length // len(key))) + key[:length % len(key)]

def vigenere_encrypt(plaintext, key, alphabet):
    ciphertext = []
    key = adjust_key_length(key, len(plaintext))
    alphabet_len = len(alphabet)
    key_indices = [alphabet.index(char) for char in key]

    for i, char in enumerate(plaintext):
        if char.upper() in alphabet:
            base = alphabet.index(char.upper())
            shift = key_indices[i]
            cipher_char = alphabet[(base + shift) % alphabet_len]
            if char.islower() and char.isalpha():
                cipher_char = cipher_char.lower()
            ciphertext.append(cipher_char)
        else:
            ciphertext.append(char)

    return ''.join(ciphertext)

def vigenere_decrypt(ciphertext, key, alphabet):
    plaintext = []
    key = adjust_key_length(key, len(ciphertext))
    alphabet_len = len(alphabet)
    key_indices = [alphabet.index(char) for char in key]

    for i, char in enumerate(ciphertext):
        if char.upper() in alphabet:
            base = alphabet.index(char.upper())
            shift = key_indices[i]
            plain_char = alphabet[(base - shift) % alphabet_len]
            if char.islower() and char.isalpha():
                plain_char = plain_char.lower()
            plaintext.append(plain_char)
        else:
            plaintext.append(char)

    return ''.join(plaintext)

def caesar_encrypt(plaintext, shift, alphabet):
    ciphertext = []
    alphabet_len = len(alphabet)

    for char in plaintext:
        if char.upper() in alphabet:
            base = alphabet.index(char.upper())
            cipher_char = alphabet[(base + shift) % alphabet_len]
            if char.islower() and char.isalpha():
                cipher_char = cipher_char.lower()
            ciphertext.append(cipher_char)
        else:
            ciphertext.append(char)

    return ''.join(ciphertext)

def caesar_decrypt(ciphertext, shift, alphabet):
    return caesar_encrypt(ciphertext, -shift, alphabet)

def aes_encrypt(plaintext, key):
    cipher = Cipher(algorithms.AES(key.ljust(32)[:32].encode()), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_plaintext = plaintext.ljust((len(plaintext) + 15) // 16 * 16)
    ciphertext = encryptor.update(padded_plaintext.encode()) + encryptor.finalize()
    return ciphertext.hex()

def aes_decrypt(ciphertext_hex, key):
    cipher = Cipher(algorithms.AES(key.ljust(32)[:32].encode()), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext_padded.decode().rstrip()

def load_custom_cipher(module_path):
    spec = importlib.util.spec_from_file_location("custom_cipher", module_path)
    custom_cipher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(custom_cipher)
    return custom_cipher

def apply_custom_cipher(cipher_module, action, text, key):
    if action == 'encrypt':
        return cipher_module.encrypt(text, key)
    elif action == 'decrypt':
        return cipher_module.decrypt(text, key)
    else:
        raise ValueError("Unknown action")

def load_custom_cipher_gui():
    module_path = filedialog.askopenfilename(filetypes=[("Python files", "*.py")])
    if not module_path:
        return

    global custom_cipher_module
    custom_cipher_module = load_custom_cipher(module_path)
    messagebox.showinfo("Custom Cipher", "Custom cipher loaded successfully!")

def process_custom_cipher():
    """Обработка текста с использованием пользовательского шифра."""
    text = text_entry.get("1.0", tk.END).strip()
    key = key_entry.get().strip()
    action = action_var.get()

    if not text or not key:
        messagebox.showerror("Ошибка", "Текст и ключ не должны быть пустыми!")
        return

    if not custom_cipher_module:
        messagebox.showerror("Ошибка", "Пользовательский шифр не загружен!")
        return

    result = apply_custom_cipher(custom_cipher_module, action, text, key)
    result_entry.delete("1.0", tk.END)
    result_entry.insert(tk.END, result)

def get_extended_alphabet(language):
    if language == 'EN':
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    elif language == 'RU':
        alphabet = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
    else:
        raise ValueError("Неподдерживаемый язык")

    # Добавляем цифры и общие символы
    extended_alphabet = alphabet + "0123456789.,!?@#&$%()-_=+*/\\'\""
    return extended_alphabet

def save_result():
    """Сохранение результата в файл."""
    result = result_entry.get("1.0", tk.END)
    filepath = filedialog.asksaveasfilename(defaultextension=".txt")
    if filepath:
        with open(filepath, 'w', encoding='utf-8') as file:
            file.write(result)

def load_text():
    filepath = filedialog.askopenfilename()
    if filepath:
        with open(filepath, 'r', encoding='utf-8') as file:
            text_entry.delete("1.0", tk.END)
            text_entry.insert(tk.END, file.read())

def load_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if not file_path:
        return

    with open(file_path, 'r', encoding='utf-8') as file:
        text = file.read()

    text_entry.delete("1.0", tk.END)
    text_entry.insert(tk.END, text)

def save_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if not file_path:
        return

    result = result_entry.get("1.0", tk.END).strip()
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(result)

def get_custom_alphabet():
    custom_alphabet = alphabet_entry.get().strip()
    if not custom_alphabet:
        return None
    return custom_alphabet.upper()

def process_caesar():
    interface_lang = interface_language_var.get()
    translation = translations[interface_lang]
    text = text_entry.get("1.0", tk.END).strip()

    try:
        shift = int(key_entry.get().strip())
    except ValueError:
        messagebox.showerror(translation['title'], translation['error_invalid_key'])
        return
    if not re.match("^[0-9]+$", str(shift)):
        raise ValueError("Key for Caesar cipher must be a number.")

    if not text:
        messagebox.showerror(translation['title'], translation['error_empty_text'])
        return

    try:
        custom_alphabet = get_custom_alphabet()
        if custom_alphabet:
            alphabet = custom_alphabet
        else:
            alphabet = get_extended_alphabet(language_var.get())
    except ValueError:
        messagebox.showerror(translation['title'], translation['error_invalid_language'])
        return

    if action_var.get() == 'encrypt':
        result = caesar_encrypt(text, shift, alphabet)
    else:
        result = caesar_decrypt(text, shift, alphabet)

    result_entry.delete("1.0", tk.END)
    result_entry.insert(tk.END, result)

def process_vigenere():
    interface_lang = interface_language_var.get()
    translation = translations[interface_lang]
    text = text_entry.get("1.0", tk.END).strip()
    key = key_entry.get().strip()

    if not text or not key:
        messagebox.showerror(translation['title'], translation['error_empty_text'])
        return

    try:
        custom_alphabet = get_custom_alphabet()
        if custom_alphabet:
            alphabet = custom_alphabet
        else:
            alphabet = get_extended_alphabet(language_var.get())
    except ValueError as e:
        messagebox.showerror(translation['title'], translation['error_invalid_language'])
        return

    if action_var.get() == 'encrypt':
        result = vigenere_encrypt(text, key, alphabet)
    else:
        result = vigenere_decrypt(text, key, alphabet)

    result_entry.delete("1.0", tk.END)
    result_entry.insert(tk.END, result)

def process_aes():
    interface_lang = interface_language_var.get()
    translation = translations[interface_lang]
    text = text_entry.get("1.0", tk.END).strip()
    key = key_entry.get().strip()

    if not text or not key:
        messagebox.showerror(translation['title'], translation['error_empty_text'])
        return

    if not (16 <= len(key) <= 32):
        raise ValueError("Key for AES must be between 16 and 32 characters long.")

    if action_var.get() == 'encrypt':
        result = aes_encrypt(text, key)
    else:
        result = aes_decrypt(text, key)

    result_entry.delete("1.0", tk.END)
    result_entry.insert(tk.END, result)

def process_vigenere_with_kasiski_examination():
    interface_lang = interface_language_var.get()
    translation = translations[interface_lang]
    text = text_entry.get("1.0", tk.END).strip()

    if not text:
        messagebox.showerror(translation['title'], translation['error_empty_text'])
        return

    try:
        custom_alphabet = get_custom_alphabet()
        if custom_alphabet:
            alphabet = custom_alphabet
        else:
            alphabet = get_extended_alphabet(language_var.get())
    except ValueError as e:
        messagebox.showerror(translation['title'], translation['error_invalid_language'])
        return

    key_length = kasiski_examination(text)
    messagebox.showinfo("Результат анализа", f"Оценка длины ключа: {key_length}")

    key = key_entry.get().strip()

    if not re.match("^[A-Z]+$", key):
        raise ValueError("Key for Vigenère cipher must contain only uppercase letters.")

    result = vigenere_decrypt(text, key, alphabet)

    result_entry.delete("1.0", tk.END)
    result_entry.insert(tk.END, result)

def test_vigenere_cipher():
    assert vigenere_encrypt("HELLO", "KEY", "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == "RIJVS"
    assert vigenere_decrypt("RIJVS", "KEY", "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == "HELLO"

def test_caesar_cipher():
    assert caesar_encrypt("HELLO", 3, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == "KHOOR"
    assert caesar_decrypt("KHOOR", 3, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == "HELLO"

def run_tests():
    test_vigenere_cipher()
    test_caesar_cipher()
    print("All tests passed.")

def process_text():
    if cipher_var.get() == 'vigenere':
        process_vigenere()
    elif cipher_var.get() == 'caesar':
        process_caesar()
    elif cipher_var.get() == 'aes':
        process_aes()

# Создание основного окна
root = tk.Tk()
root.title("Ciphers")

# Выбор языка интерфейса
interface_language_var = tk.StringVar(value='en')
interface_language_label = tk.Label(root, text="Interface language:")
interface_language_label.grid(row=0, column=0, sticky='w', padx=10, pady=5)

interface_language_en = tk.Radiobutton(root, text="English", variable=interface_language_var, value='en', command=lambda: translate_interface('en'))
interface_language_ru = tk.Radiobutton(root, text="Русский", variable=interface_language_var, value='ru', command=lambda: translate_interface('ru'))

interface_language_en.grid(row=1, column=0, sticky='w', padx=10, pady=5)
interface_language_ru.grid(row=1, column=1, sticky='w', padx=10, pady=5)

# Выбор языка шифрования
language_label = tk.Label(root, text="Select language:")
language_label.grid(row=2, column=0, sticky='w', padx=10, pady=5)

language_var = tk.StringVar(value='EN')
language_en = tk.Radiobutton(root, text="English", variable=language_var, value='EN')
language_ru = tk.Radiobutton(root, text="Русский", variable=language_var, value='RU')

language_en.grid(row=3, column=0, sticky='w', padx=10, pady=5)
language_ru.grid(row=3, column=1, sticky='w', padx=10, pady=5)

# В интерфейсе добавляем возможность выбора шифра
cipher_label = tk.Label(root, text="Ciphers:")
cipher_label.grid(row=4, column=0, sticky='w', padx=10, pady=5)

cipher_var = tk.StringVar(value='vigenere')
vigenere_radio = tk.Radiobutton(root, text="Vigenere Cipher", variable=cipher_var, value='vigenere')
caesar_radio = tk.Radiobutton(root, text="Caesar Cipher", variable=cipher_var, value='caesar')
aes_radio = tk.Radiobutton(root, text="AES Cipher", variable=cipher_var, value='aes')

vigenere_radio.grid(row=5, column=0, sticky='w', padx=10, pady=5)
caesar_radio.grid(row=5, column=1, sticky='w', padx=10, pady=5)
aes_radio.grid(row=5, column=2, sticky='w', padx=10, pady=5)

load_custom_cipher_button = tk.Button(root, text="Load Custom Cipher", command=load_custom_cipher_gui)
load_custom_cipher_button.grid(row=6, column=0, sticky='w', padx=10, pady=5)

process_custom_button = tk.Button(root, text="Process with Custom Cipher", command=process_custom_cipher)
process_custom_button.grid(row=6, column=1, sticky='w', padx=10, pady=5)

custom_cipher_module = None

# Ввод текста
text_label = tk.Label(root, text="Enter text:")
text_label.grid(row=7, column=0, sticky='w', padx=10, pady=5)

text_entry = tk.Text(root, height=5)
text_entry.grid(row=8, column=0, columnspan=4, sticky='ew', padx=10, pady=5)

# В интерфейсе добавляем поле для пользовательского алфавита
alphabet_label = tk.Label(root, text="Custom Alphabet (optional):")
alphabet_label.grid(row=9, column=0, sticky='w', padx=10, pady=5)

alphabet_entry = tk.Entry(root)
alphabet_entry.grid(row=10, column=0, columnspan=4, sticky='ew', padx=10, pady=5)

# Кнопка загрузки текста из файла
load_button = tk.Button(root, text="Load text from file", command=load_text)
load_button.grid(row=11, column=0, sticky='w', padx=10, pady=5)

# Ввод ключа
key_label = tk.Label(root, text="Enter key:")
key_label.grid(row=12, column=0, sticky='w', padx=10, pady=5)

key_entry = tk.Entry(root)
key_entry.grid(row=13, column=0, columnspan=4, sticky='ew', padx=10, pady=5)

# Выбор действия (шифрование/дешифрование)
action_var = tk.StringVar(value='encrypt')
encrypt_radio = tk.Radiobutton(root, text="Encrypt", variable=action_var, value='encrypt')
decrypt_radio = tk.Radiobutton(root, text="Decrypt", variable=action_var, value='decrypt')

encrypt_radio.grid(row=14, column=0, sticky='w', padx=10, pady=5)
decrypt_radio.grid(row=14, column=1, sticky='w', padx=10, pady=5)


# Кнопка для выполнения действия
process_button = tk.Button(root, text="Execute", command=process_text)
process_button.grid(row=15, column=0, sticky='w', padx=10, pady=5)

# Поле для вывода результата
result_label = tk.Label(root, text="Result:")
result_label.grid(row=16, column=0, sticky='w', padx=10, pady=5)

result_entry = tk.Text(root, height=5)
result_entry.grid(row=17, column=0, columnspan=4, sticky='ew', padx=10, pady=5)

# Кнопка сохранения результата в файл
save_button = tk.Button(root, text="Save result to file", command=save_result)
save_button.grid(row=18, column=0, sticky='w', padx=10, pady=5)

frequency_button = tk.Button(root, text="Frequency Analysis", command=frequency_analysis_gui)
frequency_button.grid(row=19, column=0, sticky='w', padx=10, pady=5)

guess_key_button = tk.Button(root, text="Guess Key", command=guess_key_gui)
guess_key_button.grid(row=19, column=1, sticky='w', padx=10, pady=5)

kasiski_examination_button = tk.Button(root, text="Kasiski Examination", command=process_vigenere_with_kasiski_examination)
kasiski_examination_button.grid(row=19, column=2, sticky='w', padx=10, pady=5)

load_file_button = tk.Button(root, text="Load File", command=load_file)
load_file_button.grid(row=20, column=0, sticky='w', padx=10, pady=5)

save_file_button = tk.Button(root, text="Save File", command=save_file)
save_file_button.grid(row=20, column=1, sticky='w', padx=10, pady=5)

translate_interface('en')

configure_text_widget(text_entry, font_name="Arial", font_size=12, bg_color="lightyellow", fg_color="black")
configure_text_widget(result_entry, font_name="Arial", font_size=12, bg_color="lightgrey", fg_color="black")

# Запуск основного цикла приложения
def main():
    root.mainloop()

if __name__ == "__main__":
    run_tests()
    main()