'''
This script will upload all changes to the main server repo and update the production directory ...
'''

import os
import sys


os.system('git add --all .')
os.system('git commit -m "Deploy in progress"')
os.system('git push')

if len(sys.argv) > 1: 
    if sys.argv[1] == "release":
        print("Deploying on the Main server")
        os.system('ssh nat@nylas.orgboat.com "cd sync-engine; git pull"')
    else:
        print("Unkwnown option")
else:
    print("Git push done!")
    
