import socket

# SSH sunucu bilgileri
HOST = '192.168.1.4'  # Tüm ağ arayüzlerinden bağlantı kabul eder
PORT = 2222        # SSH için özel bir port kullanıyoruz

# Kullanıcı bilgileri
USERNAME = "admin"
PASSWORD = "1234"
BANNER = "\n___       __    ___________                            \n"
BANNER += "__ |     / /_______  /__  /__________________ ________ \n"
BANNER += "__ | /| / /_  _ \\_  /__  /_  ___/  __ \\_  __ `__ \\  _ \\\n"
BANNER += "__ |/ |/ / /  __/  / _  / / /__ / /_/ /  / / / / / /  __/\n"
BANNER += "____/|__/  \\___//_/  /_/  \\___/ \\____//_/ /_/ /_/\\___/ \n"
BANNER += "                                                        \n"

def handle_client(client_socket):
    client_socket.send(b'IP Adresini girin: ')
    ip_address = client_socket.recv(1024).decode().strip()
    print(f"Bağlantı isteği IP: {ip_address}")
    
    client_socket.send(b'Kullanici adi: ')
    username = client_socket.recv(1024).decode().strip()
    client_socket.send(b'Sifre: ')
    password = client_socket.recv(1024).decode().strip()
    
    if username == USERNAME and password == PASSWORD:
        client_socket.send(BANNER.encode())
    else:
        client_socket.send(b'Hata!\n')
        client_socket.close()
        return
    
    client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"SSH sunucu {PORT} portunda dinlemede...")
    
    while True:
        client_socket, addr = server.accept()
        print(f"Yeni bağlantı: {addr}")
        handle_client(client_socket)

if __name__ == "__main__":
    start_server()
