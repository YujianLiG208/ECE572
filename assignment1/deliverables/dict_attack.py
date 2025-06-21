#!/usr/bin/env python3
import json, hashlib, argparse
from argon2 import PasswordHasher

def load_unsalted(path):
    return json.load(open(path))

def load_salted(path):
    data = json.load(open(path))
    # expect { user: { "salt": "...", "hash": "..." } }
    return data

def attack_unsalted(users, wordlist):
    cracked = {}
    for pw in open(wordlist, errors='ignore'):
        pw = pw.strip()
        h = hashlib.sha256(pw.encode()).hexdigest()
        for u, uh in users.items():
            if h == uh:
                cracked[u] = pw
        # optional early exit if all cracked
    return cracked

def attack_salted(users, wordlist):
    ph = PasswordHasher()
    cracked = {}
    for line in open(wordlist, errors='ignore'):
        pw = line.strip()
        for u, info in users.items():
            salt = info['salt']
            try:
                ph.verify(info['hash'], pw + salt)
                cracked[u] = pw
            except:
                pass
    return cracked

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('-u','--unsalted', help='unsalted JSON')
    p.add_argument('-s','--salted',   help='salted JSON')
    p.add_argument('-w','--wordlist', required=True)
    args = p.parse_args()

    if args.unsalted:
        users = load_unsalted(args.unsalted)
        print("Unsalted attack:", attack_unsalted(users, args.wordlist))

    if args.salted:
        users = load_salted(args.salted)
        print("Salted attack:", attack_salted(users, args.wordlist))