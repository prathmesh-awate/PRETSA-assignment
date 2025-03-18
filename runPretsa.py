import sys
from pretsa import Pretsa
import pandas as pd


filePath = sys.argv[1]
k = sys.argv[2]
t = sys.argv[3]
#epsilon for differential privacy
epsilon = sys.argv[4]
#user role for access control
user_role = sys.argv[5]

sys.setrecursionlimit(3000)
targetFilePath = filePath.replace(".csv","_t%s_k%s_epsilon%s_pretsa.csv" % (t,k,epsilon))

print("Load Event Log")
eventLog = pd.read_csv(filePath, delimiter=";")

if user_role == 'admin':
    print("Starting experiments with Admin privileges")
    pretsa = Pretsa(eventLog, epsilon, user_role=user_role)
    cutOutCases = pretsa.runPretsa(int(k), float(t))
    print("Modified " + str(len(cutOutCases)) + " cases for k=" + str(k))
    try:
        print("Generating Laplace Noise:")

        #getPrivatisedEventLog() calls
        privateEventLog = pretsa.getPrivatisedEventLog()
        
        privateEventLog.to_csv(targetFilePath, sep=";", index=False)
        print(f"Private event log saved to {targetFilePath}")
    except PermissionError as e:
        print(f"Access Denied: {e}")

elif user_role == 'analyst':
    print("Analyst can read the eventlog")
    print("")
    print(eventLog)

elif user_role == 'viewer':
    print("Viewer can only read the top few entries")
    print("Event Log Summary:")
    # only show a preview of the data 
    print(eventLog.head()) 
    
else:
    print("Unknown role. Please provide a valid user role.")
