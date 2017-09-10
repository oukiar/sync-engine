

# --- TIMER FOR SYNC TIMEOUT OF MAIL ACCOUNTS
mailboxes_timeouts = {}

from threading import Timer

def sync_timeout():
    print 'Executing sync account mailboxes sync timeout'
    
    for i in mailboxes_timeouts:
        if time.time() - mailboxes_timeouts[i] > 20:
            del mailboxes_timeouts[i]
                    
            # duration is in seconds
            t = Timer(10, sync_timeout)
            t.start()
            
            return
            
    # duration is in seconds
    t = Timer(10, sync_timeout)
    t.start()
    
# duration is in seconds
t = Timer(10, sync_timeout)
t.start()
