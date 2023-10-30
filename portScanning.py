from scapy.all import *
import sys 

if len(sys.argv)!= 3:
    print("uso: %s IP destino" %(sys.argv[0]))
    sys.exit(0)

target = str(sys.argv[1])
opc = str(sys.argv[2])
startport = 0
endport = 1000
filt = 0
openp = 0
closep = 0
t2 = str(target) + ".txt"
print('Escaneando '+target+' para ver puertos TCP\n')
ff = open(t2, "w")
payload = "Confirmo que verdaderamente este abierto"

# Ejercicio 2.1 
if opc == '-h':
    for x in range(startport,endport):
        packet = IP(dst=target)/TCP(sport= 2456, dport=x,flags="S")
        response = sr1(packet,timeout=0.2,verbose=0)
        # Recibo como respuesta un paquete con los flags SYN ACK 
        if response is not None and response.haslayer(TCP) and response.getlayer(TCP).flags=='SA':
            print('Puerto '+str(x)+' OPEN')
            ff.write('. '+str(x)+' OPEN')
            openp = openp + 1
        # Recibo como respuesta un paquete con el flag R
        elif response is not None and response.haslayer(TCP) and response.getlayer(TCP).flags == 'R':
            print('Puerto '+str(x)+' CLOSE')
            ff.write('. '+str(x)+' CLOSE')
            closep = closep + 1
        # No recibo respuesta 
        elif response is None:
            filt = filt + 1
            ff.write('. '+str(x)+' FILTERED')

# Ejercicio 2.2 
else: 
    for x in range(startport,endport):
        syn = 7520
        packet = IP(dst=target)/TCP(sport= 2456, dport=x, seq=syn, ack=0, flags="S")
        response = sr1(packet,timeout=0.2,verbose=0)
        # Recibo como respuesta un paquete con los flags SYN ACK 
        if response is not None and response.haslayer(TCP) and response.getlayer(TCP).flags=='SA':
            # Armo el segundo paquete con el correspondiente payload 
            packet2 = IP(dst=target)/TCP(sport= 2456, dport=x, seq=syn+1, ack=response.seq+1, flags="A")/payload  #Raw(load=payload) # esto esta bien con el seq????
            response2 = sr1(packet2,timeout=0.2,verbose=0)
            # Recibo como respuesta del segundo paquete un paquete con el flag ACK 
            if response2 is not None and response2.haslayer(TCP) and response2.getlayer(TCP).flags=='A':
                print('Puerto '+str(x)+' OPEN y puede manejar datos')
                ff.write('. '+str(x)+' OPEN')
                openp = openp + 1
            # Como respuesta del segundo paquete no recibo el ACK correspondiente 
            else : 
                print('Puerto '+str(x)+' OPEN pero no puede manejar datos')
                #Lo tomo como FILTERED
                filt = filt + 1
                ff.write('. '+str(x)+' FILTERED')
        # Recibo como respuesta un paquete con el flag R
        elif response is not None and response.haslayer(TCP) and response.getlayer(TCP).flags == 'R':
            print('Puerto '+str(x)+' CLOSE')
            ff.write('. '+str(x)+' CLOSE')
            closep = closep + 1
        # No recibo respuesta 
        elif response is None:
            filt = filt + 1
            ff.write('. '+str(x)+' FILTERED')

porcentOpen= (openp / endport) * 100
porcentFilt= (filt / endport) * 100
porcentClose = (closep / endport) * 100

print('')   
print('Escaneo completado\n')
print(f"El {porcentFilt}% son puertos Filtered y el {porcentOpen}% son puertos Open. (Puertos CLOSE:{porcentClose}%)\n")
ff.write(".\n")
ff.write(f"El {porcentFilt}% son puertos Filtered y el {porcentOpen}% son puertos Open.\n")
ff.close()