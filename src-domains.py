#!/usr/bin/python3
# -*- coding: utf-8 -*-
import sys
import argparse
from utils import banner
from utils.logger import logger
from libs.targets import update_domains
from libs.subdomain_brute import update_subdomains
from libs.all import update_all

def main():
    banner()
    parser = argparse.ArgumentParser()
    parser.add_argument('-uD', '--update-domains', dest='update_domains', help='update domains', action='store_true')
    # update all domains will take a long time
    parser.add_argument('-uDA', '--update-all-domains', dest='update_all_domains', help='update all domains', action='store_true')
    parser.add_argument('-uSD', '--update-subdomains', dest='update_subdomains', help='update subdomains', action='store_true')
    parser.add_argument('-uA', '--update-all', dest='update_all', help='update all', action='store_true')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.update_all:
        update_all()
        return
    
    if args.update_domains:
        update_domains()
    else:
        if args.update_all_domains:
            update_domains(update_all=True)

    if args.update_subdomains:
        update_subdomains()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.error('User Exit, Bye :)')