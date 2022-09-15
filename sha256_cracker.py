from pwn import *
import sys
import hashlib

if len(sys.argv) != 2:
  print("Invalid arguments!")
  print(">> {} <sha256sum>".format(sys.argv[0]))
  exit()

wanted_hash = sys.argv[1]
password_file = "rockyou.txt"
attempts = 0

with log.progress("Attemting to back: {}!\n".format(wanted_hash)) as p:
  with open(password_file, "r", encoding="latin-1") as password_list:
    for password in password_list:
      password = password.strip("\n").encode("latin-1")
      password_hash = hashlib.sha256(password).hexdigest()
      p.status("[{}] {} == {}".format(attempts, password.decode("latin-1"), password_hash))
      if password_hash == wanted_hash:
        p.success("Password hash found after {} attempts! >>>  {}  <<< hashes to {}!".format(attempts, password.decode("latin-1"), password_hash))
      attempts += 1
    p.failure("Password hash not found!")