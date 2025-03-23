import socket
import threading
import time
import datetime

# SSH sunucu bilgileri
HOST = '192.168.1.4'  # Tüm ağ arayüzlerinden bağlantı kabul eder
PORT = 2222        # SSH için özel bir port kullanıyoruz

# Kullanıcı bilgileri
USERS = {
    "admin": "1234",
    "user": "1234"
}

# Admin için banner
ADMIN_BANNER = "\n___       __    ___________                            \n"
ADMIN_BANNER += "__ |     / /_______  /__  /__________________ ________ \n"
ADMIN_BANNER += "__ | /| / /_  _ \\_  /__  /_  ___/  __ \\_  __ `__ \\  _ \\\n"
ADMIN_BANNER += "__ |/ |/ / /  __/  / _  / / /__ / /_/ /  / / / / / /  __/\n"
ADMIN_BANNER += "____/|__/  \\___//_/  /_/  \\___/ \\____//_/ /_/ /_/\\___/ \n"
ADMIN_BANNER += "                YÖNETİCİ MODU                        \n"
ADMIN_BANNER += "                                                        \n"

# User için banner
USER_BANNER = "\n  _    _                     __  __           _      \n"
USER_BANNER += " | |  | |                   |  \\/  |         | |     \n"
USER_BANNER += " | |  | |___  ___ _ __ ___  | \\  / | ___   __| |_   _ \n"
USER_BANNER += " | |  | / __|/ _ \\ '__/ __| | |\\/| |/ _ \\ / _` | | | |\n"
USER_BANNER += " | |__| \\__ \\  __/ |  \\__ \\ | |  | | (_) | (_| | |_| |\n"
USER_BANNER += "  \\____/|___/\\___|_|  |___/ |_|  |_|\\___/ \\__,_|\\__,_|\n"
USER_BANNER += "                   KULLANICI MODU                     \n"
USER_BANNER += "                                                      \n"

# Online kullanıcılar ve loglar için listeler
online_users = []  # Online kullanıcıları tutacak liste
access_logs = []   # Tüm giriş loglarını tutacak liste

# Liste kilidi (thread-safe erişim için)
lock = threading.Lock()

def display_stats():
    """Sunucu istatistiklerini periyodik olarak gösterir"""
    while True:
        # Ekranı temizlemek için
        print("\033c", end="")
        
        print("=" * 50)
        print("SSH SUNUCU İSTATİSTİKLERİ")
        print("=" * 50)
        
        # Online kullanıcılar
        print("\nONLINE KULLANICILAR:")
        print("-" * 50)
        if online_users:
            for user in online_users:
                print(f"Kullanıcı: {user['username']}, IP: {user['ip']}, Giriş Zamanı: {user['login_time']}")
        else:
            print("Şu anda online kullanıcı yok.")
        
        # Tüm loglar
        print("\nLOGLAR:")
        print("-" * 50)
        if access_logs:
            for log in access_logs:
                status = "Aktif" if log in online_users else "Çıkış Yaptı"
                print(f"Kullanıcı: {log['username']}, IP: {log['ip']}, Giriş: {log['login_time']}, Durum: {status}")
        else:
            print("Henüz log kaydı yok.")
        
        print("\n" + "=" * 50)
        
        # 5 saniyede bir güncelle
        time.sleep(5)

def add_user_to_online(username, ip):
    """Kullanıcıyı online listesine ekler"""
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user_info = {
        "username": username,
        "ip": ip,
        "login_time": current_time
    }
    
    with lock:
        online_users.append(user_info)
        access_logs.append(user_info)

def remove_user_from_online(username, ip):
    """Kullanıcıyı online listesinden çıkarır"""
    with lock:
        for user in online_users[:]:  # Listeden silme işlemi yapacağımız için kopyasını kullanıyoruz
            if user["username"] == username and user["ip"] == ip:
                online_users.remove(user)
                break

def handle_client(client_socket, addr):
    client_ip = addr[0]
    
    client_socket.send(b'IP Adresini girin: ')
    ip_address = client_socket.recv(1024).decode().strip()
    print(f"Bağlantı isteği IP: {ip_address}")
    
    client_socket.send(b'Kullanici adi: ')
    username = client_socket.recv(1024).decode().strip()
    client_socket.send(b'Sifre: ')
    password = client_socket.recv(1024).decode().strip()
    
    if username in USERS and password == USERS[username]:
        # Kullanıcıyı online listesine ekle
        add_user_to_online(username, client_ip)
        
        if username.lower() == "admin":
            client_socket.send(ADMIN_BANNER.encode())
            client_socket.send(b'\nAdmin olarak giris yaptiniz. Tum yonetici haklarina sahipsiniz.\n')
        elif username.lower() == "user":
            client_socket.send(USER_BANNER.encode())
            client_socket.send(b'\nKullanici olarak giris yaptiniz. Sinirli haklara sahipsiniz.\n')
        
        # Basit bir komut satırı oluşturalım
        try:
            while True:
                client_socket.send(f"\n{username}@server:~$ ".encode())
                command = client_socket.recv(1024).decode().strip()
                
                if not command:  # Bağlantı kesildiğinde
                    break
                
                if command.lower() == "exit" or command.lower() == "quit":
                    client_socket.send(b"Baglanti sonlandiriliyor...\n")
                    break
                elif command.lower() == "whoami":
                    client_socket.send(f"Kullanici: {username}\n".encode())
                elif command.lower() == "help":
                    client_socket.send(b"Kullanilabilir komutlar: whoami, help, exit\n")
                elif command.lower() == "users":
                    # Online kullanıcıları listele
                    response = "Online kullanıcılar:\n"
                    with lock:
                        for user in online_users:
                            response += f"- {user['username']} ({user['ip']})\n"
                    client_socket.send(response.encode())
                elif command.lower() == "logs":
                    # Tüm logları listele (sadece admin için)
                    if username.lower() == "admin":
                        response = "Tüm giriş logları:\n"
                        with lock:
                            for log in access_logs:
                                status = "Aktif" if log in online_users else "Çıkış Yaptı"
                                response += f"- {log['username']} ({log['ip']}) - {log['login_time']} - {status}\n"
                        client_socket.send(response.encode())
                    else:
                        client_socket.send(b"Yetki izniniz yok!\n")
                else:
                    client_socket.send(b"Bilinmeyen komut. Yardim icin 'help' yazin.\n")
        finally:
            # Kullanıcıyı online listesinden çıkar
            remove_user_from_online(username, client_ip)
    else:
        client_socket.send(b'Hatali kullanici adi veya sifre!\n')
    
    client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Soketi yeniden kullanılabilir yap
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"SSH sunucu {PORT} portunda dinlemede...")
    
    # İstatistikleri gösteren thread'i başlat
    stats_thread = threading.Thread(target=display_stats, daemon=True)
    stats_thread.start()
    
    try:
        while True:
            client_socket, addr = server.accept()
            print(f"Yeni bağlantı: {addr}")
            # Her bağlantı için yeni bir thread başlat
            client_thread = threading.Thread(target=handle_client, args=(client_socket, addr))
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("\nSunucu kapatılıyor...")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()
