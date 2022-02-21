# Email Notifications about too many failed logins
$EmailFrom = "";
$EmailTo = "";
$SmtpServer = ""
$SmtpPort = "";

# Active Directory Domain
$Domain = "";

# Local directory to store files and logs
$LocalDir = 'C:\AuthAudit';

# Remote file share for centralized log keeping
$RemoteLogDir = "\\path\to\log\files";

# Name to give email alert record file
$EmailAlertLog = 'EmailAlerts.log';

# Number of failed logins to allow before sending an alert. If not triggered, will reset each new month.
[int]$AlertThreshold = 3;

# Whether or not to check for potentially missed logs the month prior
$CheckMonthBefore = $true;

# Source IPs for to ignored failed attempts from.
# Typically used to reduce alert spam resulting from a vulnerability scanner
$IgnoredIps = @(
    ''
    ''
    ''
    ''
);


####################################################################################################
# Variable Declarations
####################################################################################################
Clear-Host;
Function FetchAuth {
    param (
        [datetime]$Earliest,
        [datetime]$Latest,
        [string]$FileDate
    )

    $AuthEvents = @();
    $FailedLogins = 0;

    $SerialNumber = (Get-WMIObject -Class Win32_BIOS).SerialNumber;

    $DeviceName = hostname;

    $HostLogDir = "$RemoteLogDir\hostname\$(hostname)";
    $HostLogFile = "$HostLogDir\$(hostname)_$($FileDate)_Auth.log";

    $SnLogDir = "$RemoteLogDir\serial\$($SerialNumber)";
    $SnLogFile = "$SnLogDir\$($SerialNumber)_$($FileDate)_Auth.log";

    $LocalLogFile = "$LocalDir\Logs\Auth\($FileDate)_Auth.log";

    $EmailAlertLog = "$LocalDir\$EmailAlertLog";

    $EmailParams = @{
        From=$EmailFrom;
        To=$EmailTo;
        Subject="";
        Body="";
        SMTPServer=$SmtpServer;
        port=$SmtpPort;
    }

    $ScriptLogDir = "$RemoteLogDir\scriptLog\$SerialNumber\$(hostname)";
    $ScriptLogFile = "$ScriptLogDir\$(hostname)_$($SerialNumber)_$($FileDate)_Auth.log";


####################################################################################################
# Log Function 
####################################################################################################
    Function WriteLog {
        param( [String] $Log, [Object[]] $Data )
        $Date = ((Get-Date -UFormat "%d-%b-%Y_%T") -replace ':', '-');
        Switch -WildCard ($Log) {
            "*success*" { Write-Host "[$Date] $Log" -f "Green"; }
            "*ERROR*" { Write-Host "[$Date] $Log" -f "Red"; }
            "*NEW*" { Write-Host "[$Date] $Log" -f "Yellow"; }
            Default { Write-Host "[$Date] $Log" -f "Magenta"; }
        }
        If ($Data) { $Data = ($Data | Out-String).Trim().Split("`n") | ForEach-Object { Write-Host "`t$_"}; }
        If ($Log) { Add-Content $ScriptLogFile "[$Date] $Log"; }
        If ($Data) {
            ($Data | Out-String).Trim().Split("`n") | ForEach-Object { Add-Content $ScriptLogFile ("`t" + "$_".Trim()) };
        }
    }
    WriteLog -Log "------------------------------ $(Get-Date -UFormat "%d-%b-%Y %T %Z") ------------------------------";
    WriteLog -Log "$(hostname) > $($PSScriptRoot)"
    WriteLog -Log "Fetching Authentication Logs from $Earliest to $Latest";


####################################################################################################
# Check if Directory and File Exist 
####################################################################################################
    WriteLog -Log "Checking for Directories and Files...";
    Function CheckFiles  {
        param( [Object] $Dir, [Object] $File, [String] $User)
        Try {
            $Dir | ForEach-Object { 
                If (-NOT (Test-Path -Path $_)){ 
                    New-Item -ItemType Directory -Path $_;
                    If ($User -AND $DeviceName -notlike 'EPS-112') {
                        $EmailParams.Subject = "New User Login - $($User)";
                        $EmailParams.Body = $html+"$($DeviceName)<br><br>$($User) Log file Created.<br><br>$($Dir)";
                        Send-MailMessage @EmailParams -BodyAsHtml;
                    }
                }
            }
            $File | ForEach-Object {
                If (-NOT (Test-Path -Path $_ -PathType Leaf)) { 
                    New-Item -ItemType File -Path $_ -Force;
                    Add-Content $_ "Log File Created:  $(Get-Date)";
                    Add-Content $_ "____________________________________________________________________________________________________________________________________________________________________________________";
                    If($_ -ne $ScriptLogFile) {
                        Add-Content $_ "|    EventId     |        Time         |           Event             |             User               |     Origin IP     |    Origin Host    |     Hostname     |    Serial#     |";
                        Clear-Content -Path $EmailAlertLog;
                    }
                }
            }
        } Catch { WriteLog -Log "[ERROR] Error with Directories and Files." -Data $_; }
    }
    CheckFiles -Dir $LocalDir, $ScriptLogDir, $RemoteLogDir, $HostLogDir, $SnLogDir, $ScriptLogDir -File $EmailAlertLog, $LocalLogFile, $HostLogFile, $SnLogFile, $ScriptLogFile


####################################################################################################
# Failed Authentication Events
####################################################################################################
    WriteLog -Log "Fetching Failed Authentication Events...";
    Try {
        Get-WinEvent -FilterHashtable @{
            LogName='Security'; 
            Id=@(4625); 
            StartTime=$Earliest; 
            EndTime=$Latest;
        } -ErrorAction SilentlyContinue | Select-Object * | ForEach-Object {
            $IpAddress = @('127.0.0.1',$_.Properties[19].Value)[($null -ne $_.Properties[19].Value)];
            If ($IgnoredIps -NotContains $IpAddress) { $FailedLogins++; }
            $AuthEvents += New-Object PSObject -Property @{
                EventId = $_.RecordId;
                Time = Get-Date $_.TimeCreated -UFormat "%d-%b-%Y %R";
                Event = "4625 (Login Failed)";
                User = "$(@($_.Properties[6].Value,".")[!$_.Properties[6].Value];)\$($_.Properties[5].Value)";
                OriginIp = $IpAddress;
                OriginHost = '';
                HostName = hostname;
                HostSN = $SerialNumber;
                InvalidUser = $true;
            }
        }
    } Catch { WriteLog -Log "[ERROR] Error with Failed Authentication Events." -Data $_; }


####################################################################################################
# Privilege Use Events
####################################################################################################
    <#
    Get-WinEvent -FilterHashtable @{
        LogName='System'; 
        Id=@(4672); 
        StartTime=$Earliest; 
        EndTime=$Latest;
    } -ErrorAction SilentlyContinue | Select * | ForEach-Object {
        $_
        $AuthEvents += New-Object PSObject -Property @{
            EventId=$_.RecordId
            Time = Get-Date $_.TimeCreated -UFormat "%d-%b-%Y %R";
            Event = "4625 (Login Failed)";
            User = "$(@($_.Properties[6].Value,".")[!$_.Properties[6].Value];)\$($_.Properties[5].Value)";
            OriginIp = @('127.0.0.1',$_.Properties[19].Value)[$_.Properties[19].Value -ne $null];
            InvalidUser = $true;
        }
    }
    #>


####################################################################################################
# Lock/Unlock Events
####################################################################################################
    WriteLog -Log "Fatching Lock/Unlock Events...";
    Try {
        Get-WinEvent -FilterHashtable @{ 
            LogName='Security'; 
            Id=@(4800,4801); 
            StartTime=$Earliest; 
            EndTime=$Latest;
        } -ErrorAction SilentlyContinue | Select-Object * | ForEach-Object {
            Switch ($_.Id) {
                4800 { $AuthEvent = "4800 (Lock)"; }
                4801 { $AuthEvent = "4801 (Unlock)"; }
            }
            $AuthEvents += New-Object PSObject -Property @{
                EventId=$_.RecordId
                Time = Get-Date $_.TimeCreated -UFormat "%d-%b-%Y %R";
                Event = $AuthEvent;
                User = "$($_.Properties[2].Value)\$($_.Properties[1].Value)";
                OriginIp = '127.0.0.1';
                OriginHost = '';
                HostName = hostname;
                HostSN = $SerialNumber;
                InvalidUser = $true;
            }
        }
    } Catch { WriteLog -Log "[ERROR] Error with Lock/Unlock Events." -Data $_; }


####################################################################################################
# Reconnect/Disconnect Events
####################################################################################################
    WriteLog -Log "Fatching Reconnect/Disconnect Events...";
    Try {
        Get-WinEvent -FilterHashtable @{ 
            LogName='Security'; 
            Id=@(4778,4779); 
            StartTime=$Earliest; 
            EndTime=$Latest; 
        } -ErrorAction SilentlyContinue | Select-Object * | ForEach-Object {
            Switch ($_.Id) {
                4778 { $AuthEvent = "4778 (Session Reconnect)"; }
                4779 { $AuthEvent = "4779 (Session Disconnect)"; }
            }
            $AuthEvents += New-Object PSObject -Property @{
                EventId=$_.RecordId
                Time = Get-Date $_.TimeCreated -UFormat "%d-%b-%Y %R";
                Event = $AuthEvent;
                User = "$($_.Properties[1].Value)\$($_.Properties[0].Value)";
                OriginIp = "$($_.Properties[5].Value)";
                OriginHost = "$($_.Properties[4].Value)";
                HostName = hostname;
                HostSN = $SerialNumber;
                InvalidUser = $true;
            }
        }
    } Catch { WriteLog -Log "[ERROR] Error with Reconnect/Disconnect Events." -Data $_; }


####################################################################################################
# Shutdown Events
####################################################################################################
    <#
    WriteLog -Log "Fatching Shutdown Events...";
    Try {
        Get-WinEvent -FilterHashtable @{ 
            LogName='System'; 
            ID=@(41,6006,6008); 
            StartTime=$Earliest; 
            EndTime=$Latest;
        } -ErrorAction SilentlyContinue | Select-Object * | ForEach-Object {
            $_.Properties.Value;
            Switch ($_.Id) {
                41 { $AuthEvent = " 41  (Error Shutdown)"; }
                1074 { $AuthEvent = "1074 (App Forced Shutdown)"; }
                6006 { $AuthEvent = "6006 (Clean Shutdown)"; }
                6008 { $AuthEvent = "6008 (Unclean Shutdown)"; }
            }
            $AuthEvents += New-Object PSObject -Property @{
                EventId=$_.RecordId
                Time = Get-Date $_.TimeCreated -UFormat "%d-%b-%Y %R";
                Event = $AuthEvent;
                User = (New-Object System.Security.Principal.SecurityIdentifier $_.Properties[1].Value.Value).Translate([System.Security.Principal.NTAccount]).Value;
                OriginIp = '127.0.0.1';
                OriginHost = '';
                HostName = hostname;
                HostSN = $SerialNumber;
                InvalidUser = $true;
            }
        }
    } Catch { WriteLog -Log "[ERROR] Error with Logon/Logoff Events." -Data $_; }
    #>


####################################################################################################
# Logon/Logoff Events
####################################################################################################
    WriteLog -Log "Fatching Logon/Logoff Events...";
    Try {
        Get-WinEvent -FilterHashtable @{ 
            LogName='System'; 
            ID=@(7001,7002); 
            StartTime=$Earliest; 
            EndTime=$Latest;
        } -ErrorAction SilentlyContinue | Select-Object * | ForEach-Object {
            #$_
            If ($_.Properties[1].Value.Value -like "S-*") {
                Switch ($_.Id) {
                    7001 { $AuthEvent = "7001 (Logon)"; }
                    7002 { $AuthEvent = "7002 (Logoff)"; }
                }
                $AuthEvents += New-Object PSObject -Property @{
                    EventId=$_.RecordId
                    Time = Get-Date $_.TimeCreated -UFormat "%d-%b-%Y %R";
                    Event = $AuthEvent;
                    User = (New-Object System.Security.Principal.SecurityIdentifier $_.Properties[1].Value.Value).Translate([System.Security.Principal.NTAccount]).Value;
                    OriginIp = '127.0.0.1';
                    OriginHost = '';
                    HostName = hostname;
                    HostSN = $SerialNumber;
                    InvalidUser = $true;
                }
            }
        }
    } Catch { WriteLog -Log "[ERROR] Error with Logon/Logoff Events." -Data $_; }


####################################################################################################
# Remote Desktop Authentication Events
####################################################################################################
    WriteLog -Log "Fatching Remote Desktop Authentication Events...";
    Try {
        Get-WinEvent -FilterHashtable @{
            LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; 
            Id=@(1149,1150,1148); 
            StartTime=$Earliest; 
            EndTime=$Latest;
        } -ErrorAction SilentlyContinue | Select-Object * | ForEach-Object {
            Switch ($_.Id) {
                1149 { $AuthEvent = "1149 (RDP Logon)"; }
                1150 { $AuthEvent = "1150 (RDP Logon Failure)"; }
                1148 { $AuthEvent = "1148 (RDP Logon Merged)"; }
            }
            $AuthEvents += New-Object PSObject -Property @{
                EventId=$_.RecordId
                Time = Get-Date $_.TimeCreated -UFormat "%d-%b-%Y %R";
                Event = $AuthEvent;
                User = "$($_.Properties[1].Value)\$($_.Properties[0].Value)";
                OriginIp = $_.Properties[2].Value;
                OriginHost = '';
                HostName = hostname;
                HostSN = $SerialNumber;
                InvalidUser = $true;
            }
        }

        # Removing Events 21,23,24,25 because These seem to be thrown whether remote or local. 
        <#Get-WinEvent -FilterHashtable @{
            LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational';
            Id=@(21,23,24,25); 
            StartTime=$Earliest; 
            EndTime=$Latest;
        } -ErrorAction SilentlyContinue | Select-Object * | ForEach-Object {
            Switch ($_.Id) {
                21 { $AuthEvent = " 21  (RDP Logon)"; }
                23 { $AuthEvent = " 23  (RDP Logoff)"; }
                24 { $AuthEvent = " 24  (RDP Disconnect)"; }
                25 { $AuthEvent = " 25  (RDP Reconnect)"; }
            }
            $AuthEvents += New-Object PSObject -Property @{
                EventId=$_.RecordId
                Time = Get-Date $_.TimeCreated -UFormat "%d-%b-%Y %R";
                Event = $AuthEvent;
                User = $_.Properties[0].Value;
                OriginIp = @('127.0.0.1',$_.Properties[2].Value)[($_.Properties[2].Value -ne $null)];
                OriginHost = '';
                HostName = hostname;
                HostSN = $SerialNumber;
                InvalidUser = $true;
            }
        }
        #>
    } Catch { WriteLog -Log "[ERROR] Error with Remote Desktop Authentication Events." -Data $_; }


####################################################################################################
# Sanitize Usernames
####################################################################################################
    ForEach ($Event in $AuthEvents) {
        If ($Event.User -like "$($Domain)*") {
            $UserToCheck = ($Event.User).Split('\')[1];
            Try {
                Get-ADUser $UserToCheck | Out-Null;
                $Event.InvalidUser = $false;
            } Catch {
                $Event.InvalidUser = $true;
                $LegitUser = '';
                $UserCharArray = $UserToCheck.ToCharArray();
                $CharNum = 0;
                Do {
                    $LegitUser = $LegitUser+$UserCharArray[$CharNum];
                    Try {
                        Get-ADUser $LegitUser | Out-Null;
                        $Event.User = $LegitUser;
                        $Event.InvalidUser = $false;
                    } Catch {
                        $CharNum++;
                        If ($CharNum -gt 20) { Break; }
                    }
                } While ($Event.InvalidUser);
            }
        }
    }


####################################################################################################
# Check Logs and Write Missing Logs
####################################################################################################
    WriteLog -Log "Checking Logs and Writing Missing Logs...";
    Try {
        $AuthEvents = $AuthEvents | Sort-Object Time;
        $AuthEvents | ForEach-Object {
            $Log = "|  $("$($_.EventId)".PadLeft(12,"0"))  |  $($_.Time)  |  $(($_.Event).padRight(25))  |  $(($_.User).padRight(28))  |  $(($_.OriginIp).padRight(15))  |  $(($_.OriginHost).padRight(15))  |  $(($_.HostName).padRight(14))  |  $(($_.HostSN).padRight(12))  |";
            $LocalLogFile, $HostLogFile, $SnLogFile | ForEach-Object {
                If (-NOT (Select-String -Path $_ -Pattern "$Log" -SimpleMatch)) { 
                    Add-Content $_ $Log; 
                    WriteLog -Log "Missing Log:   $Log";
                }
            }
            If (!$_.InvalidUser -OR $_.User -eq 'Administrator') {
                $User = ($_.User).Split('\')[1];
                $UserLogDir = "$($RemoteLogDir)\user\$($User -replace '[^\w-]', '')";
                $UserLogFile = "$($UserLogDir)\$($User -replace '[^\w-]', '')_$($FileDate)_Auth.log";
                CheckFiles -Dir $UserLogDir -File $UserLogFile -User "'$($_.User)'";
                If (-NOT (Select-String -Path $UserLogFile -Pattern "$Log" -SimpleMatch)) { 
                    Add-Content $UserLogFile $Log; 
                    WriteLog -Log "Missing Log:   $Log";
                }
            }
        }
    } Catch { WriteLog -Log "[ERROR] Error Checking Logs and Writing Missing Logs." -Data $_; }


####################################################################################################
# Email Alerts for High Count Failed Authorization Attempts
####################################################################################################
    WriteLog -Log "Checking to see if an Email Alert needs to be Sent...";
    Try {
        $LastEmailAlert = $null;
        $PrevAlertFailed = 0;
        If ($FailedLogins -ge $AlertThreshold) {
            $LastEmailAlert = Get-Content -Path $EmailAlertLog;
            If ($LastEmailAlert) {
                $LastAlert = $LastEmailAlert.Split('|');

                $PrevAlertFailed = @(0,$LastAlert[0])[($null -ne $LastAlert[0])];
            }
            If (!$LastEmailAlert -OR $FailedLogins -ge ($PrevAlertFailed + $AlertThreshold)) {
                $html = '<style type="text/css">th{text-align: left; border-bottom: 1pt solid black; padding:0 8px;} td{padding:0 8px;}</style>';
                "$($FailedLogins )|$(Get-Date)" | Out-File -FilePath $EmailAlertLog -Force;
                $EmailParams.Subject = "High Number of Failed Logins - $(hostname)";
                $EmailParams.Body = $html+"Hostname: $(hostname)`n`n"+($AuthEvents | Where-Object { $_.OriginIp -ne '128.186.25.7' } | Sort-Object Time | Select-Object EventId,Time,Event,User,OriginIp | ConvertTo-Html -AS Table | Out-String);
                Send-MailMessage @EmailParams -BodyAsHtml;
                "$($FailedLogins)|$(Get-Date)" | Out-File -FilePath $EmailAlertLog -Force;
            }
        }
    } Catch { WriteLog -Log "[ERROR] Error sending Email Alert." -Data $_; }

    WriteLog -Log "----------------------------------------- End ----------------------------------------";
}

$EarliestLog = Get-Date -Day 1 -Hour 0 -Minute 0 -Second 0;

If ($CheckMonthBefore) {
    $StartTime = ((Get-Date -Date $EarliestLog).AddMonths(-1));
    $EndTime = (Get-Date -Date $EarliestLog -Hour 23 -Minute 59 -Second 59).AddDays(-1);
    FetchAuth -Earliest $StartTime -Latest $EndTime -FileDate (Get-Date -Date $EndTime -UFormat "%Y-%b");
}

FetchAuth -Earliest $EarliestLog -Latest (Get-Date) -FileDate (Get-Date -UFormat "%Y-%b");

Exit 0;
