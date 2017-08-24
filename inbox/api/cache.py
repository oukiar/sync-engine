from flask.ext.cache import Cache    
cache = Cache()

cache_ram = {}

def get_cached(data):
    hashval = hash(frozenset( data ))
    if hashval in cache_ram:
        return cache_ram[hashval]
    else:
        return None
    
def set_cached(data, result):
    hashval = hash(frozenset( data ))
    cache_ram[hashval] = result
