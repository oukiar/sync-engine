from flask.ext.cache import Cache    
cache = Cache()

cache_ram = {}

def get_cached(data):
    hashval = hash(frozenset( data ))
    print('GETING: ', hashval)
    
    if hashval in cache_ram:
        print(cache_ram[hashval])
        return cache_ram[hashval]
    else:
        return None
    
def set_cached(data, result):
    hashval = hash(frozenset( data ))
    cache_ram[hashval] = result
    
