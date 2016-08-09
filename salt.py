import random
import string
import hashlib

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

# Implement the function valid_pw() that returns True if a user's password
# matches its hash. You will need to modify make_pw_hash.

def make_pw_hash(name, pw):
    salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    ###Your code here
    sha = h.split(',')[0]
    salt = h.split(',')[1]
    if hashlib.sha256(name + pw +salt).hexdigest() == sha:
        return True
    else:
        return False



h = make_pw_hash('spez', 'hunter2')
print h.split(',')
#print valid_pw('spez', 'hunter2', h)
