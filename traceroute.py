from scapy.all import * 
import sys 

def traceroute(host):
    max_hops = 30  # Número máximo de saltos
    ttl = 0

    print(f"Rastreando la ruta hacia {host}:")
    dest_ip = socket.gethostbyname(host)

    while ttl <= max_hops:
        # Construye un paquete ICMP Echo Request con el valor de TTL actual
        packet = IP(dst=host, ttl=ttl) / ICMP(type=8, code=0)

        # Envía el paquete y espera una respuesta o un timeout
        reply = sr1(packet, timeout=10)

        if reply is None:
            # Si no se recibe respuesta, muestra un asterisco
            print(f"{ttl}: No recibi respuesta ")
        else:
            # Si se recibe una respuesta, muestra la dirección IP del host
            print(f"Numero de ttl : {ttl}, IP del host : {reply.src}")

            if reply.src == dest_ip:
                # Hemos llegado al host de destino
                print(f"Hemos llegado al host {host} destino, su IP es : {reply.src}")
                break

        ttl += 1

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Ejecuto: python3 traceroute.py <host>")
        sys.exit(1)

    host = sys.argv[1]
    traceroute(host)
