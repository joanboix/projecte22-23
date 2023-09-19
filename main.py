# -*- coding: utf-8 -*-


import shodan
import requests
import sys
import json
import subprocess
from subprocess import call
import nmap
import datetime
import telebot
import os


from sys import exit
from pyfiglet import Figlet


token = "5837911762:AAGwfeM3XtJbDCT99u1bbP10R52Z5vYMGZs"

bot = telebot.TeleBot(token)


@bot.message_handler(commands=['start'])
def send_file(message):
    chat_id = message.chat.id
    file_paths = ["/home/alumne/PycharmProjects/JCJ/resultats.json", "/home/alumne/PycharmProjects/JCJ/resultats_ssh-audit.json", "/home/alumne/PycharmProjects/JCJ/resultats_enum4linux.json"]

    for file_path in file_paths:
        with open(file_path, 'rb') as file:
            bot.send_document(chat_id, file)

    

@bot.message_handler(commands=['stop'])
def handle_stop(message):
    chat_id = message.chat.id
    message_id = message.message_id

    for i in range(5):
        bot.delete_message(chat_id, message_id - i)

    print(banner.renderText("# JCJ #"))
    os._exit(0)



api = shodan.Shodan('bviEFb02tSmkiEXLMhXxCLO66SHgFxSh')

banner = Figlet(font='isometric4')

data = datetime.date.today()
datastring = data.strftime("%d-%m-%Y")
format_data = "Auditoria realitzada a data de " + datastring

f = open("resultats.json", "w")
f.write(format_data + "\n")
def shodan1():
    dnsresolve = 'https://api.shodan.io/dns/resolve?hostnames=' + domini_objectiu + '&key=' + (
        'q4OUWnLVtDwydVw6mWAFgKU4H0H4mnA9')

    try:
        resolved = requests.get(dnsresolve)        
        print(resolved.json())

        hostip = resolved.json()[domini_objectiu]

        host = api.host(hostip)

        #f = open("resultats.json", "a")
        f.write("\n" + "##~ DADES ~##" + "\n")
        f.write("IP: %s" % host['ip_str'] + "\n")
        f.write("Organization: %s" % host.get('org', 'n/a') + "\n")
        # f.close()

        print("IP: %s" % host['ip_str'])
        print("Nom de l'organització: %s" % host.get('org',
                                                     'n/a'))

    finally:
        "Error"


def shodan2():
    dnsresolve = 'https://api.shodan.io/dns/resolve?hostnames=' + domini_objectiu + '&key=' + (
        'q4OUWnLVtDwydVw6mWAFgKU4H0H4mnA9')
    resolved = requests.get(dnsresolve)
    hostip = resolved.json()[domini_objectiu]

    host = api.host(hostip)
    #f = open("resultats.json", "a")
    f.write("\n" + "##~ LLISTAT DE PORTS ~##" + "\n")
    for item in host['data']:
        print("Port: %s" % item['port'])
        f.write("Port: %s" % item['port'] + "\n")
    # f.close()


def shodan3():
    dnsresolve = 'https://api.shodan.io/dns/resolve?hostnames=' + domini_objectiu + '&key=' + (
        'q4OUWnLVtDwydVw6mWAFgKU4H0H4mnA9')
    resolved = requests.get(dnsresolve)
    hostip = resolved.json()[domini_objectiu]

    host = api.host(hostip)
    #f = open("resultats.json", "a")
    f.write("\n" + "##~ SERVEIS VINCULATS A PORTS ~##" + "\n")
    for item in host['data']:
        print("Port: %s" % item['port'])
        f.write("Port: %s" % item['port'] + "\n")
        objecte = item['data'].split("\n")
        print(objecte[0])
        f.write(objecte[0] + "\n")


def shodan4():
    facets = [

        'port',
        'ip'
    ]

    facet_titles = {

        'port': 'Ports més comuns:',
        'ip': 'IP més comuns:'
    }

    if len(sys.argv) == 1:
        print('Usage: %s <search query>' % sys.argv[0])
        sys.exit(1)

    try:

        query = ' '.join(sys.argv[1:])

        result = api.count(query, facets=facets)
        #f = open("resultats.json", "a")
        f.write("\n" + "##~ PORTS I IP COMUNS D'UN SEVREI ~##" + "\n")
        f.write("servei escanejat: " + sys.argv + "\n")
        f.write("Total Results: %s\n" % result['total'] + "\n")

        print('Total Results: %s\n' % result['total'])

        for facet in result['facets']:
            print(facet_titles[facet])
            f.write(facet_titles[facet] + "\n")

            for term in result['facets'][facet]:
                print('%s: %s' % (term['value'], term['count']))
                f.write('%s: %s' % (term['value'], term['count']) + "\n")

            print(" ")
    finally:

        print(' ')

def nmap1():
    nm = nmap.PortScanner()
    network = input("Introdueix la xarxa a escanejar (ex: 192.168.1.0/24): ")
    nm.scan(hosts=network, arguments='-n -sP')
    hosts_list = nm.all_hosts()
    #f = open("resultats.json", "a")
    f.write("\n" + "##~ HOSTS DE LA XARXA " +network + " ~##" + "\n")
    print("Els hosts trobats són:")
    for host in hosts_list:
        print(host)
        f.write(host + "\n")


def nmap2():
    nm = nmap.PortScanner()
    target = input("Introdueix la IP o el nom del host a escanejar: ")
    nm.scan(hosts=target, arguments='-n -sS -sV -p-')
    #f = open("resultats.json", "a")
    f.write("\n" + "##~ ESCANEIG DE PORTS OBERTS DEL HOST " +target + " ~##" + "\n")
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            open_ports = nm[host]['tcp'].keys()
            print(f"Ports oberts en {host}:")
            for port in open_ports:
                print(f"- Port {port} ({nm[host]['tcp'][port]['name']})")
                f.write(f"- Port {port} ({nm[host]['tcp'][port]['name']})\n")


def nmap3():
    nm = nmap.PortScanner()
    target = input("Introdueix la IP o el nom del host a escanejar: ")
    port_range = input("Introdueix el rang de ports a escanejar (ex: 80,443 o 1-1024): ")
    nm.scan(hosts=target, arguments='-n -sS -sV -p' + port_range)
    #f = open("resultats.json", "a")
    f.write("\n" + "##~ ESCANEIG DELS SERVEIS DEL RANG DE PORTS " +port_range + " DEL HOST" +target + " ~##" + "\n")
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            open_ports = nm[host]['tcp'].keys()
            print(f"Serveis i versions trobats en {host}:")
            for port in open_ports:
                print(
                    f"- Port {port} ({nm[host]['tcp'][port]['name']}): {nm[host]['tcp'][port]['product']} {nm[host]['tcp'][port]['version']}")
                f.write(f"- Port {port} ({nm[host]['tcp'][port]['name']}): {nm[host]['tcp'][port]['product']} {nm[host]['tcp'][port]['version']}\n")


def nmap4():
    nm = nmap.PortScanner()
    target = input("Introdueix la IP o el nom del host a escanejar: ")
    port = input("Introdueix el port a escanejar: ")
    nm.scan(hosts=target, arguments='-n -sS -sV -p' + port)
    f = open("resultats.json", "a")
    f.write("\n" + "##~ VULNERABILITAT DEL SERVEI SITUAT AL PORT " +port + " DEL HOST " +target + " ~##" + "\n")
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            service_name = nm[host]['tcp'][int(port)]['name']
            print(f"Vulnerabilitats trobades en {host} ({service_name}):")
            vulnerabilities = nm[host]['tcp'][int(port)]
            for vulnerability in vulnerabilities:
                print(f"- {vulnerability} : {vulnerabilities[vulnerability]}")
                f.write(f"- {vulnerability} : {vulnerabilities[vulnerability]}\n")



print(banner.renderText("# JCJ #"))
print("##Benvinguts al programa de monitorització de xarxa de JCJ##")
print("##Versió 1.0##")
print("##Programat per Cinta Z, Jaume G, Joan B##")
print("##Programa defensiu dissenyat per neutralitzar possibles amenaces," "\n" "  reforçar la seguretat del sistema i garantir l'integritat dels" 
      "\n" "  dispositius i serveis de la xarxa. \n")



print("Escull una de les següents opcions:\n")


def menuprincipal():
    print("1 -- Shodan Api")
    print("2 -- Escaneig")
    print("3 -- Auditoria SSH")
    print("4 -- Ennumeració")
    print("5 -- Rebre resultats i sortir")
    print("0 -- Sortir sense resultats")


while True:
    menuprincipal()
    option = int(input())
    if option == 1:
        print("Has escollit el menú de Shodan. Ara, escull una de les següents opcions:\n")


        def menushodan():
            print("1 -- Cerca d'informació de l'api de Shodan")
            print("2 -- Noms de domini i ports oberts")
            print("3 -- Servei relacionat a cada port")
            print("4 -- A quines IP i quins ports puc trovar aquest servei?")
            print("5 -- Tornar al menú principal")
            print("6 -- Rebre resultats i sortir")
            print("0 -- Sortir sense resultats")


        while True:
            menushodan()
            option = int(input())
            if option == 1:
                domini_objectiu = str(input("Insereix un objectiu en format (www.iesebre.com)\n"))
                shodan1()


            elif option == 2:
                domini_objectiu = str(input("Insereix un objectiu en format (www.iesebre.com)\n"))
                shodan2()

            elif option == 3:
                domini_objectiu = str(input("Insereix un objectiu en format (www.iesebre.com)\n"))
                shodan3()

            elif option == 4:
                sys.argv = (input("Insereix el servei que vols escanejar.\n"))
                shodan4()

            elif option == 5:
                break

            elif option == 6:
                f.close()
                print("Pots trobar els resultats accedint al següent enllaç: https://t.me/JCJaudit_bot")
                bot.polling()

            elif option == 0:
                f.close()
                os._exit(0)


    elif option == 2:

        print("Has escollit el menú d'escaneig. Ara, escull una de les següents opcions:\n")


        def menunmap():
            print("1 -- Descobrir hosts de xarxa")
            print("2 -- Escaneig de ports oberts")
            print("3 -- Llistat de serveis i versions d'un, un rang o tots els ports.")
            print("4 -- Llistat de vulnerabilitats d'un, un rang o tots els serveis.")
            print("5 -- Tornar al menú principal")
            print("6 -- Rebre resultats i sortir.")
            print("0 -- Sortir sense resultats.")


        while True:
            menunmap()
            option = int(input())
            if option == 1:
                nmap1()

            elif option == 2:
                nmap2()

            elif option == 3:
                nmap3()

            elif option == 4:
                nmap4()

            elif option == 5:
                break

            elif option == 6:
                f.close()
                print("Pots trobar els resultats accedint al següent enllaç: https://t.me/JCJaudit_bot")
                bot.polling()

            elif option == 0:
                f.close()
                os._exit(0)

    elif option == 3:
        equip_objectiu = str(input("Sobre quin equip vols fer l'auditoria? "))

        scriptssh_path = '/home/alumne/PycharmProjects/JCJ/ssh-audit/ssh-audit.py'
        subprocess.call(['python3', scriptssh_path , equip_objectiu], stdout=open('resultats_ssh-audit.json', 'w'))

        print("S'ha completat amb èxit l'auditoria SSH. Pots trobar els resultats al fitxer resultats_ssh-audit.json")

    elif option == 4:

        ip = str(input("Sobre quin equip vols fer l'auditoria? "))

        os.environ['PATH'] += ':/snap/bin/enum4linux'  

        command = f'enum4linux {ip}'
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        output_file = 'resultats_enum4linux.json'
        with open(output_file, 'w') as file:
            file.write(result.stdout)

        print("S'ha completat amb èxit l'auditoria amb enum4linux. Pots trobar els resultats al fitxer resultats_enum4linux.json")


    elif option == 5:
        f.close()
        print("Accedeix a https://t.me/JCJaudit_bot i segueix les instruccions per veure els resultats.")
        bot.polling()
        
    elif option == 0:
        f.close()
        print(banner.renderText("# JCJ #"))
        os._exit(0)
        
