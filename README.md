# WindowsAuthAudit
Script to pull authentication logs (including RDP) from windows desktop or server event logs and write them to easily readable logs files. 

Script will create log files to keep track of authentication events by device hostname, device serial number, and domain username.

Script will send an alert if it sees three failed login attempts. 

![Screenshot 2022-02-21 101716](https://user-images.githubusercontent.com/58618324/154983051-5b403e2f-c582-46e6-89d0-2846369860a2.png)

Script names files relative to the directory and separates logs by month. i.e. xxxx_2022-Feb_Auth.log

![image](https://user-images.githubusercontent.com/58618324/154983187-33b363de-835c-4f4b-8edb-20b6c17ae225.png)


Recommendations:
- Require all powershell scripts to be signed in your domain environment. Set through Group Policy. 
- Sign this script with an organization code signing certificate that is pushed to all domain assets via GPO.
- Run as a scheduled task pushed to all domain assets with a GPO.
- A minimum, set the scheduled task to trigger on user login and on event 4625 (failed login). 
- Log directory requires a minimum of Read and Write permissions. This script **DOES NOT** require Modify prmissions. Nothing in existing logs files needs to be modified or deleted. This script just writes to existing files. 

