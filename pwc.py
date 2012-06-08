#!/usr/bin/python
"""
Python Whois Checker
@author Jason Gabriele
"""
import sys
import os
import pywhois
from optparse import OptionParser
import sqlite3
import re
import datetime
import time
import socket

#Global Funcs
#Print out list of domains
def format_domains(domains):
  domain_list = "%s\tExpires On\tReg?\n" % "Domain Name".ljust(40)
  for d in domains:
    expires = d['expires']
    if expires == None:
      expires = "N/A       "
    else:
      expires = datetime.datetime( *time.strptime( expires, '%Y-%m-%d' )[0:5] ).strftime( '%m/%d/%Y' )
    domain_list += "%s\t%s\t%s\n" % ( d['hostname'].ljust(40), expires, "Yes" if d['registered'] else "No" )
  return domain_list

#Get info from pywhois
def get_whois(domain):
  i = { 'registered': False, 'expires': None }
  info = pywhois.whois(domain)
  if info.status:
    i['registered'] = True
    dformat = '%d-%b-%Y'
    if len(info.expiration_date[0]) > 11:
      dformat = '%a %b %d %H:%M:%S %Z %Y'
    i['expires'] = datetime.datetime.strptime(info.expiration_date[0], dformat)
  else:
    return info.text 
  return i

#Close out process and exit
def exit_and_close(s, code):
  s.close()
  sys.exit(code)

#Optparse Settings
u = """%prog [options] command
Commands:
     list: List all of the domains
     export: List all domains separated by newlines
     add: Add a domain name to be monitored
     delete: Remove a domain
     listupcoming: List domains which expire in the next few weeks
     check: Check for domains which are set to expire soon and send an email if necessary"""

parser = OptionParser(usage=u)
parser.add_option("-v", "--verbose", dest="quiet", action="store_false", default=True, help="Show debug messages")
parser.add_option("-e", "--email", dest="emailto", default=os.getenv('USER'), help="Set a custom email address for messages")
parser.add_option("-d", "--days-til-expire", dest="days", default=14, type="int", help="Number of days within the domain will expire")
parser.add_option("-f", "--from", dest="emailfrom", default="PWC <" + os.getenv('USER') + "@" + socket.getfqdn() + ">", help="Sender of email")
(options, args) = parser.parse_args()

#Available Commands
whois_commands = ['list','add','delete','listupcoming','check','export']

#Check if command was set and is a valid command
if len(args) < 1:
  parser.error("You must specify a command to run")
  sys.exit(1)

try:
  whois_commands.index(args[0])
except ValueError:
  parser.error("%s is not a valid command" % args[0])
  sys.exit(1)

cmd = args[0]

#Get User's Home Directory
home = os.getenv( 'HOME' )
#Connect to Sqlite db
con = sqlite3.connect( home + '/.pwc.db', isolation_level=None ) #Set autocommit
con.row_factory = sqlite3.Row
sql = con.cursor()

#Check for tables
if not sql.execute('SELECT * FROM sqlite_master').fetchone():
  #Create tables
  sql.execute("""CREATE TABLE domains (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   hostname VARCHAR(255) NOT NULL,
                   expires DATE,
                   registered boolean NOT NULL
                 )""")

#Check domain format
if cmd == "add" or cmd == "delete":
  if len(args) < 2:
    parser.error("You must specify a domain to modify")
    exit_and_close(sql, 1)

  domain = args[1]

  #Check to see if domain is in the correct format
  if not re.match("^([a-zA-Z0-9-]+)\.(com|us|net|org|info|biz|co\.uk|kr)$", domain):
    parser.error("You must specify a domain in the format yahoo.com - Leave off any www's")
    exit_and_close(sql, 1)

#Display a list of monitored domains
if cmd == "list" or cmd == "export":
  sql.execute("SELECT * FROM domains ORDER BY expires ASC")
  domains = sql.fetchall()
  
  if cmd == "list":
    if len(domains) == 0:
      if not options.quiet: 
        print "No domains are being monitored"
      exit_and_close(sql, 0)
    print format_domains(domains)
  else:
    for d in domains:
      print "%s" % d['hostname']

#Add a domain to be monitored
elif cmd == "add":
  #Check if entry already exists
  sql.execute("SELECT * FROM domains WHERE hostname = ?", [domain])
  if sql.fetchone():
    print "%s is already being tracked" % domain
    exit_and_close(sql, 1)
 
  #Get info for the domain 
  info = get_whois(domain)

  #Make sure if returned ok
  if type(info) == str:
    print "Failure to lookup domain %s" % domain
    print "---"
    print info
    exit_and_close(sql, 1)
  
  #Finally, insert the domain
  sql.execute("INSERT INTO domains (hostname,expires,registered) VALUES (?,?,?)", [ domain, 
                                                                                    info['expires'].strftime("%Y-%m-%d") if info['expires'] else None, 
                                                                                    int(info['registered']) ])
 
  if not options.quiet: 
    print "%s added to monitoring list." % domain,
    if info['registered']:
      print "This domain is registered and expires on %s." % info['expires'].strftime("%m/%d/%Y")
    else:
      print "This domain isn't registered."

#Remove a domain from monitoring
elif cmd == "delete":
  #Check if domain is being monitored
  sql.execute("SELECT * FROM domains WHERE hostname = ?", [ domain ])
  domains = sql.fetchall()

  if len(domains) == 0:
    print "This domains isn't being monitored"
    exit_and_close(sql, 1)

  sql.execute("DELETE FROM domains WHERE hostname = ?", [ domain ])
  
  if not options.quiet:
    print "%s has been removed from the monitoring list" % domain

#List domains which are expiring soon
elif cmd == "listupcoming" or cmd == "check":
  #Loop through and update domains
  sql.execute("""SELECT * FROM domains
                 ORDER BY expires ASC,
                          hostname ASC""")
  domains = sql.fetchall()

  if len(domains) == 0:
    if not options.quiet:
      print "No domains being monitored"
    exit_and_close(sql, 0)
  
  if not options.quiet:
    print "Updating %d domains..." % len(domains)  

  exp_domains = []
  time_diff = datetime.datetime.today() + datetime.timedelta(days=options.days)
  for d in domains:
    info = get_whois(d['hostname'])

    #Make sure if returned ok
    if type(info) == str:
      print "Failure to lookup domain %s" % domain
      print "---"
      print info
      exit_and_close(sql, 1)

    sql.execute("""UPDATE domains
                   SET registered=?,
                       expires=?
                   WHERE hostname=?""", 
                      [ 1 if info['registered'] else 0, 
                        info['expires'].strftime("%Y-%m-%d") if info['expires'] else None, 
                        d['hostname'] ])

    #Check to see if the expires date is in range
    if not info['registered'] or info['expires'] <= time_diff:
      exp_domains.append(d)

    #Print out progress
    if not options.quiet:
      print "%s (%s, %s)" % (d['hostname'],
                                      "Registered" if info['registered'] else "Not Registered",
                                      info['expires'].strftime("%Y-%m-%d") if info['expires'] else "N/A" )
  
  #If no domains are expiring soon, then quit
  if len(exp_domains) == 0:
    if not options.quiet:
      print "No domains expiring soon"
    exit_and_close(sql, 0)

  output = format_domains(exp_domains)
  if cmd == "listupcoming":
    print output
    exit_and_close(sql, 0)

  #Send email
  recipients = options.emailto
  sender = options.emailfrom

  #Send mail using the sendmail command 
  p = os.popen("/usr/bin/sendmail -t", "w")
  p.write("From: %s\n" % sender)
  p.write("To: %s\n" % recipients)
  p.write("Subject: [PWC] Domains Expiring Soon\n")
  p.write("\n")
  p.write(output)
  status = p.close()

#Close the sqlite3 connection
sql.close()
