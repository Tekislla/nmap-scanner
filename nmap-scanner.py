import nmap

# Criando um objeto do Nmap
scanner = nmap.PortScanner()

# Definindo o endereço IP da máquina virtual
ip_address = "127.0.0.1"

# Execute uma verificação do tipo SYN
scanner.scan(ip_address, arguments="-sS -p 1-1000")

# Iterando pelos dados e imprimindo as informações relevantes no txt
with open("scanner_tcp.txt", "w") as open_file:
    for port in scanner[ip_address]["tcp"]:
        open_file.write(f"Porta {port}: {scanner[ip_address]['tcp'][port]['name']} - Estado: {scanner[ip_address]['tcp'][port]['state']} \n")

# Escrevendo dados no arquivo csv
with open("scanner_tcp.csv", "w") as open_file:
    open_file.write(scanner.csv())

# Executando uma verificação do tipo UDP
scanner.scan(ip_address, arguments="-sU -p 1-1000")

# Iterando pelos dados e imprimindo as informações relevantes no txt
with open("scanner_udp.txt", "w") as open_file:
    for port in scanner[ip_address]["udp"]:
        open_file.write(f"Porta {port}: {scanner[ip_address]['udp'][port]['name']} - Estado: {scanner[ip_address]['udp'][port]['state']} \n")

# Escrevendo dados no arquivo csv
with open("scanner_udp.csv", "w") as open_file:
    open_file.write(scanner.csv())
