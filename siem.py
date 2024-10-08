# siem.py is een script dat de siem database vult en analyzeert
#
# mvdl versie 1 07-05-2024
###############################################################

import psycopg2
import glob
import re
import shutil
import smtplib
import subprocess
import traceback
import os
from email.message import EmailMessage
from datetime import date,datetime

conn = psycopg2.connect(host='localhost',database='siem',user='siem',password='**********')
emailmessage = "Hier de dagelijkse analyze van de snmplogs : \n\n\n\n"
debugmessage = "Hier de dagelijkse analyze in debug : \n\n\n\n"

# indexeer alle beschikbare logfilesi van gister
gloober = "/var/log/network-*.log"
baseid = 0

#  sommige servers spuwen zoveel log dat het script het bewerken van een running log
# niet bijhoud. Dus eerst moven en dan pas inlezen...

listallelogfiles = glob.glob(gloober)
for origineel in listallelogfiles:
         shutil.move(origineel, "/var/log/siem-archive/")
subprocess.call(["systemctl", "restart", "rsyslog"])

gloober2 = "/var/log/siem-archive/network-*.log"
listalleteverwerken = glob.glob(gloober2)


for logfile in listalleteverwerken:
                print (str(logfile))
                host=re.search("\d+\.\d+\.\d+\.\d+",logfile).group(0)
                hosttabelnaam="a" + host.replace(".","_")
                meldingen = {}

                #check of er al een tabel bestaat voor deze host
                query = "Select max(id) from " + hosttabelnaam

                try:
                                cursor = conn.cursor()
                                cursor.execute(query)
                                print("tabel aanwezig")
                                baseid = float(cursor.fetchone()[0])
                                if (baseid is None) or (baseid==0):
                                                baseid=1
                                cursor.close()
                except psycopg2.Error as err:
                                print("rollback")
                                conn.rollback()
                                try:
                                                cquery = "CREATE TABLE " + hosttabelnaam + " (id bigserial primary key, datum timestamp, service varchar(200), eventid int, message text)"
                                                exccursor = conn.cursor()
                                                exccursor.execute(cquery)
                                                conn.commit()
                                                totaal = 1
                                except psycopg2.Error as err:
                                                print(err)
                                                exit(1)


                LOGFILE=open(logfile,"r")
                for line in LOGFILE:
                        try:
                                # vind service en eventid
                                infopart=re.search("#011.*#015", line).group(0)
                                infoparts = infopart.split("#011")
                                geschoondelijn = line.replace("\"","_")
                                geschoondelijn = geschoondelijn.replace("\'","_")

                                insertquery = 'INSERT INTO ' +  hosttabelnaam +  ' (service, eventid, datum,  message) VALUES (\'' + infoparts[6] + '\', \'' + infoparts[5] + '\', \'' + infoparts[4] + '\', \'' + geschoondelijn + '\')'
                                insertcursor = conn.cursor()
                                insertcursor.execute(insertquery)
                        except Exception as e:
                                  debugmessage = debugmessage + str(traceback.format_exc())
                                  print(str(traceback.format_exc()))

                # commit verhuisd na hele actie niet na elke insert
                # minder veilig, wel veel sneller
                conn.commit()
                insertcursor.close()


                # logfile verwerkt, start analyze

                # vind eerst alle id/servicecombinaties
                meldingtupiescursor = conn.cursor()
                meldingtupiescursor.execute("Select distinct service,eventid from " +  hosttabelnaam + " where id>" + str(baseid))
                # print ("tupies-query : Select distinct service,eventid from " +  hosttabelnaam + " where id>" + str(baseid))

                debugmessage = debugmessage + "\n hostname : " + host

                if baseid==0:
                        baseid = 0.0001

                for (service,evenid) in meldingtupiescursor:
                        # bereken basisfrequentie van deze meldingen

                        freqcursor = conn.cursor()
                        freqcursor.execute("select count(*) from " +  hosttabelnaam + " where service=\'"+ service +"\' AND eventid=\'"+ str(evenid) + "\' AND id<="+str(baseid))
                        totalfreq = (int(freqcursor.fetchone()[0]))/baseid
                        freqcursor.close()

                        # doe hetzelfde voor de nieuwe meldingen
                        # eerst aantal nieuwe meldingen tellen
                        freqcursor = conn.cursor()
                        freqcursor.execute("select MAX(id) from " + hosttabelnaam)
                        newbaseid = int(freqcursor.fetchone()[0])
                        freqcursor.close()
                        freqcursor = conn.cursor()
                        freqcursor.execute("select count(*) from " +  hosttabelnaam + " where service=\'"+ service +"\' AND eventid=\'"+ str(evenid) + "\' AND id>"+str(baseid))
                        currentfreq = (int(freqcursor.fetchone()[0]))/(newbaseid-baseid)
                        freqcursor.close()

                        #print (service + ": " + str(evenid) + " : current freq = " + str(currentfreq) + " : normal freq = " + str(totalfreq))
                        debugmessage = debugmessage + "\n" + service + ": " + str(evenid) + " : current freq = " + str(currentfreq) + " : normal freq = " + str(totalfreq)


                        if currentfreq > (1.98 * totalfreq):
                                meldingen[service] = evenid

                meldingtupiescursor.close()
                if len(meldingen) > 0:
                                emailmessage = emailmessage + "\n meldingen die veel voorkomen voor " + host
                                for key in meldingen:
                                           emailmessage = emailmessage + "\n" + str(key) + ", " + str(meldingen[key])

                destlogfile = logfile[9:] + str(datetime.now())[:10]
                os.rename(logfile, "/var/log/" + destlogfile)

conn.close()


msg = EmailMessage()
msg.set_content(emailmessage)
msg['Subject'] = "logfile analyse"
msg['From'] = "server@ivdnt.loc"
msg['To'] = "systeembeheer@ivdnt.org"

s = smtplib.SMTP('aa.bb.cc.dd')
s.send_message(msg)
s.quit()


# msg2 = EmailMessage()
#msg2.set_content(debugmessage)
#msg2['Subject'] = "logfile analyse (debug)"
#msg2['From'] = "server@ivdnt.loc"
#msg2['To'] = "systeembeheer@ivdnt.org"

#s = smtplib.SMTP('aa.bb.cc.dd')
#s.send_message(msg2)
#s.quit()
