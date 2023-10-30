from scapy.all import *
import sys, time

def traceroute(host):
    max_hops = 30  # Establezco el número máximo de saltos, en este caso 30
    ttl = 0     
    print(f"Rastreando la ruta hacia {host}:")
    dest_ip = socket.gethostbyname(host)

    while ttl <= max_hops:
        # Calculo el tiempo inicial antes de enviar el paquete 
        start_time = time.time()
        # Construye un paquete ICMP con el valor de TTL actual y el host pasado por consola
        packet = IP(dst=host, ttl=ttl) / ICMP(type=8, code=0)
        reply = sr1(packet, timeout=10)

        if reply is None:
            print(f"{ttl}: No recibí respuesta ")
        else:
            # Si se recibe una respuesta, muestra la dirección IP del host y el RTT
            end_time = time.time()
            rtt = (end_time - start_time) * 1000  # Calculo el RTT en milisegundos
            print(f"Numero de ttl : {ttl}, IP del host : {reply.src}, RTT: {rtt:.2f} ms")

            if reply.src == dest_ip:
                print(f"Hemos llegado al host destino : {reply.src}")
                break
        ttl += 1

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("La cantidad de argumentos no es correcta")
        sys.exit(1)

    host = sys.argv[1]
    traceroute(host)