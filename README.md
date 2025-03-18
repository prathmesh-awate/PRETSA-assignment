# README: Pretsa with Differential Privacy and Access Control

This project extends the PRETSA framework by integrating **Differential Privacy** and **Access Control** are added to enhance the data protection capabilities of PRETSA. 

The goal is to enhance the existing framework's privacy guarantees while introducing user role-based access control (RBAC) for secure usage. 

## Features
- **Differential Privacy**(https://programming-dp.com/ch3.html ):
File: presta.py
Functions : __generateLaplaceNoise, __generateNewAnnotation, getPrivatisedEventLog (check comments for explaination)
Adds differential privacy to your dataset, ensuring that data analysis does not reveal sensitive information about individuals within the dataset.
- **Access Control**(https://www.fortinet.com/resources/cyberglossary/access-control): 
File : authorization.py and presta.py
Functions: check_access

Checks user privileges whenever needed - Admin: modify, view all and view summary , Analyst: View All and Viewer: View Summary
Introduces an admin authentication system using hashed passwords for secure execution of the algorithm.

## Requirements
To run our algorithm you need the following Python packages:
- Pandas (https://pandas.pydata.org/index.html)
- SciPy (https://www.scipy.org)
- NumPy (http://www.numpy.org)
- AnyNode (https://anytree.readthedocs.io/en/latest/)
- bcrypt (https://pypi.org/project/bcrypt/)

```
Install Requirements: pip install -r requirements.txt
```
## How to run PRETSA with Differential Privacy and Access Control ##

1. To run the algorithm you first have to initiate the *Pretsa* class and hand over an event log represented as a pandas dataframe:
```
eventLog = pd.read_csv(filePath, delimiter=";")
pretsa = Pretsa(eventLog)
```
2. Run the PRETSA algorithm with your choosen k-anonymity, t-closesness parameter, differential privacy epsilon factor and the user role. If the user has access to modify the logs the algorithm returns the cases that have been modified: 
```
cutOutCases = pretsa.runPretsa(k,t)
```
Finally we can return our privatizied event log as a pandas dataframe:
```
privateEventLog = pretsa.getPrivatisedEventLog()
```

```
Run Command: python runPretsa.py <fileName> <k> <t> <epsilon> <user_role>
```
Parameters:
k-anonymity: Minimum k-anonymity threshold to be enforced.
t-closeness: The t-closeness parameter for privacy enforcement.
epsilon: The epsilon value for differential privacy.
user_role: The role of the user (e.g., analyst, admin).

Note : If you restart the algorithm the last password will still work as the hashed value is still stored in the password_hash.txt(storing it in an environment variable would solve this problem but I wanted to make it persistent). If you want to reset the password just delete the password_hash.txt file.

I used the baselogs provided in the original repository saved as baselog.zip, extract the files and run this command
```
Example Command:
python3 runPresta.py ./baselogs/bpic2013_dataset.csv 3 0.5 0.8 admin
```

## What's Happening? ##

Differential Privacy: 
The key function __generateLaplaceNoise applies noise to sensitive values based on the epsilon parameter in __generateNewAnnotation and getPrivatisedEventLog to create differentially private events.
Access Control
The Role-Based Access Control (RBAC) system defines three roles:

Admin: Can modify event logs, view all records, and access summaries.
Analyst: Can view all records.
Viewer: Can only access summaries.

The check_access function enforces these permissions, prevents unauthorized users from accessing sensitive data. Password authentication using bcrypt hashing ensures secure role validation, and passwords persist across sessions using password_hash.txt.

With these features PRETSA now supports both privacy-preserving data anonymization and controlled access to sensitive information, making it more secure and compliant with privacy regulations.