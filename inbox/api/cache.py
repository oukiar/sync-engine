from flask.ext.cache import Cache    
cache = Cache()

import json
import time
from threading import Timer

cache_ram = {}
cache_timeouts = {}

def get_cached(data):
    hashval = json.dumps( data )
    print('GETING: ', hashval)
    
    if hashval in cache_ram:
        print('CACHE_RAM', cache_ram[hashval])
        cache_ram[hashval]['data']['last_access'] = time.time()
        return cache_ram[hashval]['data']
    else:
        return None
    
def set_cached(data, result, timeout=60):
    last_access = time.time()
    
    hashval = json.dumps( data )
    cache_ram[hashval] = {'last_access':last_access, 'timeout':timeout, 'data':result}
    
def garbage_collector():
    print 'Executing garbage collector' 
    
    for i in cache_ram:
        if cache_ram[i]['timeout'] > time.time() - cache_ram[i]['last_access']:
            print('---- Removing from cache: ', i)
            del cache_ram[i]
    
# duration is in seconds
t = Timer(30, garbage_collector)
t.start()
