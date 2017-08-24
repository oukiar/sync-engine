from flask.ext.cache import Cache    
cache = Cache()
import json

cache_ram = {}
cache_timeouts = {}

def get_cached(data):
    hashval = json.dumps( data )
    print('GETING: ', hashval)
    
    if hashval in cache_ram:
        print('CACHE_RAM', cache_ram[hashval])
        return cache_ram[hashval]
    else:
        return None
    
def set_cached(data, result, timeout=60):
    hashval = json.dumps( data )
    cache_ram[hashval] = result
    
