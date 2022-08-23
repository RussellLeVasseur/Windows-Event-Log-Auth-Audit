param (
    [Object]$ConfigFile=''
)

If (!$ConfigFile) { 
    Write-Error "You did not provide a config file!";
    Write-Error "Use the flag '-ConfigFile' and provide a completed config."
    Write-Error "Exiting..."
    Start-Sleep -Seconds 10; Exit 1; 
}

$Config = (Get-Content $ConfigFile) | ConvertFrom-Json;

$EmailParams = @{
    From=$Config.EmailParams.From;
    To=$Config.EmailParams.To;
    SMTPServer=$Config.EmailParams.SMTPServer;
    port=$Config.EmailParams.Port;
}
$RandomNumber = (Get-Random -Minimum 0 -Maximum 60)*5;

####################################################################################################
# Variable Declarations
####################################################################################################
Clear-Host;
$ScriptStart = Get-Date;
$RandomNumber = (Get-Random -Minimum 0 -Maximum 60)*5;
$Win32_BIOS = Get-WMIObject -Class Win32_BIOS;
$Win32_BaseBoard = Get-WmiObject -Class Win32_BaseBoard;
If ($Win32_BIOS.SerialNumber -eq "System Serial Number") {
    $SerialNumber = ($Win32_BaseBoard.SerialNumber -replace '[\\/]','').Trim(); }
} Else { $SerialNumber = $Win32_BIOS.SerialNumber; }
$ScriptLogDir = "$($Config.RemoteLogDir)\scriptLog\$SerialNumber\$DeviceName";
$ScriptLogFile = "$ScriptLogDir\$($DeviceName)_$($SerialNumber)_$(Get-Date -UFormat "%Y-%b")_Auth.log";

If (-NOT (Test-Path -Path "$($Config.LocalDir)\FailedEmailAlert.json" -PathType Leaf)) { 
    Write-Host "No log file!"
    New-Item -ItemType File -Path "$($Config.LocalDir)\FailedEmailAlert.json" -Force;
    $DefaultData = [Hashtable]@{
        "$((Get-Date -UFormat "%b%Y"))" = [PSCustomObject]@{
            Last_Notified = (Get-Date -Day 1 -Hour 0 -Minute 0 -Second 0).DateTime;
            Failed_Count = 0;
        }
    };
    Set-Content -Path "$($Config.LocalDir)\FailedEmailAlert.json" -Value ($DefaultData | ConvertTo-Json);
    $FailedEmailAlerts = (Get-Content -Path "$($Config.LocalDir)\FailedEmailAlert.json" | ConvertFrom-Json); 
} Else { $FailedEmailAlerts = (Get-Content -Path "$($Config.LocalDir)\FailedEmailAlert.json" | ConvertFrom-Json); }


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
WriteLog -Log "$DeviceName > $PSScriptRoot"

Function ValidateUser {
    param( [PSCustomObject] $User);
        If ($User.Username -like "$($Config.Domain)*") {
            $UserToCheck = (($User.Username).Split('\')[1]).Trim();
            Try {
                Get-ADUser $UserToCheck | Out-Null;
                $User.Invalid = $false;
                return $User;
            } Catch {
                $LegitUser = '';
                $UserCharArray = $UserToCheck.ToCharArray();
                $CharNum = 0;
                Do {
                    $LegitUser = $LegitUser+$UserCharArray[$CharNum];
                    Try {
                        Get-ADUser $LegitUser | Out-Null;
                        $User.Username = "$(($User.Username).Split('\')[0])\$($LegitUser)";
                        $User.Invalid = $false;
                        return $User;
                    } Catch {
                        $CharNum++;
                        If ($Charnum -ge $UserCharArray.Length -OR $CharNum -gt 20) {
                            $ToReplace = $UserToCheck.Substring(3,$UserToCheck.Length-6);
                            $User.Username = "$(($User.Username).Split('\')[0])\$($UserToCheck -replace $ToReplace,'********')";
                            return $User;
                        }
                    }
                } While ($User.Invalid);
            }
        }
    return $User;
}


########################################################################################################################################################################################################
# Modules Requirements 
########################################################################################################################################################################################################
#WriteLog -Log "Checking Required Modules...";
$RequiredModules = 'PSSQLite';
$RequiredModules | ForEach-Object {
    Try {
        $Mdle = $_;
        #WriteLog -Log "Checking for $Mdle...";
        If (!(Get-Module -ListAvailable -Name $Mdle)) {
            WriteLog -Log "$Mdle not found. Installing...";
            Install-Module -Name $Mdle -Force;
        } Else {
            $Latest = [String](Find-Module -Name $Mdle | Sort-Object Version -Descending)[0].version;
            $Installed = [String](Get-Module -ListAvailable $Mdle | Select-Object -First 1).version;
            If ([System.Version]$Latest -gt [System.Version]$Installed) {
                WriteLog -Log "[UPDATE] Updating $($Mdle)...";
                Update-Module -Name $Mdle -Force;
            }
        }
        Try { Import-Module -Name $Mdle -Force; }
        Catch {
            WriteLog -Log "[ERROR] Unable to Import $($Mdle) Module." -Data $_;
            EmailAlert -Subject "[ERROR] Importing Module" -Body "$($_ | Out-String)";
        }
    } Catch { WriteLog -Log "[ERROR] $($_ | Out-String)"; }
}
WriteLog -Log "Requirements Installed and Loaded.";


####################################################################################################
# Fetch Auth Function 
####################################################################################################
Function FetchAuth {
    param (
        [datetime]$Earliest,
        [datetime]$Latest,
        [string]$FileDate,
        [int]$AlertThreshold = $Config.AlertThreshold
    )
    WriteLog -Log "Fetching Authentication Logs from $Earliest to $Latest";
    $AuthEvents = @();
    $FailedLogins = 0;

    $Query = "CREATE TABLE IF NOT EXISTS Users (username VARCHAR(20) PRIMARY KEY, lastLogin int(30))"
    Invoke-SqliteQuery -Query $Query -DataSource $DataSource

    $DeviceName = hostname;
    $HostLogDir = "$($Config.RemoteLogDir)\hostname\$($DeviceName)";
    $HostLogFile = "$HostLogDir\$($DeviceName)_$($FileDate)_Auth.log";
    $SnLogDir = "$($Config.RemoteLogDir)\serial\$($SerialNumber)";
    $SnLogFile = "$SnLogDir\$($SerialNumber)_$($FileDate)_Auth.log";
    $LocalLogFile = "$($Config.LocalDir)\Logs\$($FileDate)_Auth.log";

    If (!$FailedEmailAlerts."$((Get-Date -Date $Earliest -UFormat "%b%Y"))") {
        $FailedEmailAlerts | Add-Member -MemberType NoteProperty -Name "$((Get-Date -Date $Earliest -UFormat "%b%Y"))" -Value @{
            Last_Notified = (Get-Date -Date $Earliest -Day 1 -Hour 0 -Minute 0 -Second 0).DateTime;
            Failed_Count = 0;
        }
        Set-Content -Path "$($Config.LocalDir)\FailedEmailAlert.json" -Value ($FailedEmailAlerts | ConvertTo-Json);
    }
    $LastEmailAlert = $FailedEmailAlerts."$((Get-Date -Date $Earliest -UFormat "%b%Y"))";
    

####################################################################################################
# Check if Directory and File Exist 
####################################################################################################
    WriteLog -Log "Checking for Directories and Files...";
    Function CheckFiles  {
        param( [Object] $File, [String] $User)
        Try {
            $File | ForEach-Object {
                If (-NOT (Test-Path -Path $_ -PathType Leaf)) { 
                    New-Item -ItemType File -Path $_ -Force;
                    Add-Content $_ "Log File Created:  $(Get-Date)";
                    Add-Content $_ "____________________________________________________________________________________________________________________________________________________________________________________";
                    If($_ -ne $ScriptLogFile) {
                        Add-Content $_ "|    EventId     |        Time         |           Event             |             User               |     Origin IP     |    Origin Host    |     Hostname     |    Serial#     |";
                    }
                }
            }
        } Catch { WriteLog -Log "[ERROR] Error with Directories and Files." -Data $_; }
    }
    CheckFiles -File $LocalLogFile, $HostLogFile, $SnLogFile, $ScriptLogFile


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
            If ($Config.IgnoredIps -NotContains $IpAddress) { $FailedLogins++; }
            $AuthEvents += New-Object PSObject -Property @{
                EventId = $_.RecordId;
                Time = Get-Date $_.TimeCreated -UFormat "%d-%b-%Y %R";
                Event = "4625 (Login Failed)";
                Username ="$(@($_.Properties[6].Value,".")[!$_.Properties[6].Value];)\$($_.Properties[5].Value)";
                OriginIp = $IpAddress;
                OriginHost = '';
                HostName = $DeviceName;
                HostSN = $SerialNumber;
                Invalid = $true;
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
            Username ="$(@($_.Properties[6].Value,".")[!$_.Properties[6].Value];)\$($_.Properties[5].Value)";
            OriginIp = @('127.0.0.1',$_.Properties[19].Value)[$_.Properties[19].Value -ne $null];
            Invalid = $true;
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
                Username ="$($_.Properties[2].Value)\$($_.Properties[1].Value)";
                OriginIp = '127.0.0.1';
                OriginHost = '';
                HostName = $DeviceName;
                HostSN = $SerialNumber;
                Invalid = $true;
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
                Username ="$($_.Properties[1].Value)\$($_.Properties[0].Value)";
                OriginIp = "$($_.Properties[5].Value)";
                OriginHost = "$($_.Properties[4].Value)";
                HostName = $DeviceName;
                HostSN = $SerialNumber;
                Invalid = $true;
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
                Username =(New-Object System.Security.Principal.SecurityIdentifier $_.Properties[1].Value.Value).Translate([System.Security.Principal.NTAccount]).Value;
                OriginIp = '127.0.0.1';
                OriginHost = '';
                HostName = $DeviceName;
                HostSN = $SerialNumber;
                Invalid = $true;
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
            If ($_.Properties[1].Value.Value -like "S-*") {
                Switch ($_.Id) {
                    7001 { $AuthEvent = "7001 (Logon)"; }
                    7002 { $AuthEvent = "7002 (Logoff)"; }
                }
                $AuthEvents += New-Object PSObject -Property @{
                    EventId=$_.RecordId
                    Time = Get-Date $_.TimeCreated -UFormat "%d-%b-%Y %R";
                    Event = $AuthEvent;
                    Username =(New-Object System.Security.Principal.SecurityIdentifier $_.Properties[1].Value.Value).Translate([System.Security.Principal.NTAccount]).Value;
                    OriginIp = '127.0.0.1';
                    OriginHost = '';
                    HostName = $DeviceName;
                    HostSN = $SerialNumber;
                    Invalid = $true;
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
                Username ="$($_.Properties[1].Value)\$($_.Properties[0].Value)";
                OriginIp = $_.Properties[2].Value;
                OriginHost = '';
                HostName = $DeviceName;
                HostSN = $SerialNumber;
                Invalid = $true;
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
                Username =$_.Properties[0].Value;
                OriginIp = @('127.0.0.1',$_.Properties[2].Value)[($_.Properties[2].Value -ne $null)];
                OriginHost = '';
                HostName = $DeviceName;
                HostSN = $SerialNumber;
                Invalid = $true;
            }
        }
        #>
    } Catch { WriteLog -Log "[ERROR] Error with Remote Desktop Authentication Events." -Data $_; }


####################################################################################################
# Check Logs and Write Missing Logs
####################################################################################################
    WriteLog -Log "Checking Logs and Writing Missing Logs to $FileDate files...";
    $AuthEvents = $AuthEvents | Sort-Object Time;
    ForEach ($Event in $AuthEvents) {
        If (($Earliest).Month -eq (Get-Date -Date $Event.Time).Month) {
            $User = ValidateUser -User $Event;
            $Log = "|  $("$($User.EventId)".PadLeft(12,"0"))  |  $($User.Time)  |  $(($User.Event).padRight(25))  |  $(($User.Username).padRight(28))  |  $(($User.OriginIp).padRight(15))  |  $(($User.OriginHost).padRight(15))  |  $(($User.HostName).padRight(14))  |  $(($User.HostSN).padRight(12))  |";
            $HostLogFile, $SnLogFile, $LocalLogFile | ForEach-Object {
                If (-NOT (Select-String -Path $_ -Pattern "$Log" -SimpleMatch)) { 
                    Add-Content $_ $Log; 
                    WriteLog -Log "Missing Log:   $Log";
                }
            }
            If (!$User.Invalid -OR $User.Username -eq '.\Administrator') {
                $User = ($User.Username).Split('\')[1];
                $UserLogDir = "$($($Config.RemoteLogDir))\user\$($User -replace '[^\w-]', '')";
                $UserLogFile = "$($UserLogDir)\$($User -replace '[^\w-]', '')_$($FileDate)_Auth.log";
                $UserLogDirs += $UserLogDir;
                CheckFiles -Dir $UserLogDir -File $UserLogFile -User "'$($User.Username)'";
                If (-NOT (Select-String -Path $UserLogFile -Pattern "$Log" -SimpleMatch)) { 
                    Add-Content $UserLogFile $Log; 
                    WriteLog -Log "Missing Log:   $Log";
                }
            }
        }
    }
    $UserLogDirs = $UserLogDirs | Select-Object -Unique;


####################################################################################################
# Email Alerts for High Count Failed Authorization Attempts
####################################################################################################
    WriteLog -Log "Checking to see if an Email Alert needs to be sent...";
    Try {
        If ($FailedLogins -ge $Config.AlertThreshold) {
            If ($FailedLogins -ge ($LastEmailAlert.Failed_Count + $Config.AlertThreshold)) {
                $html = '<style type="text/css">th{text-align: left; border-bottom: 1pt solid black; padding:0 8px;} td{padding:0 8px;}</style>';
                $EventTable = $AuthEvents | Where-Object { $_.OriginIp -ne '128.186.25.7' } | Sort-Object Time | Select-Object EventId,Time,Event,Username,OriginIp | ConvertTo-Html -AS Table | Out-String;
                $EmailParams.Subject = "High Number of Failed Logins - $DeviceName";
                $EmailParams.Body = $html+"Hostname: $DeviceName<br>Logs by Hostname: $HostLogFile<br>Logs by Serial: $SnLogFile<br>Logs by Users: $($UserLogDirs -join '<br>             ')<br><br>"+$EventTable;
                Send-MailMessage @EmailParams -BodyAsHtml;
                $LastEmailAlert.Last_Notified = (Get-Date).DateTime;
                $LastEmailAlert.Failed_Count = $FailedLogins;
                Set-Content -Path "$($Config.LocalDir)\FailedEmailAlert.json" -Value ($FailedEmailAlerts | ConvertTo-Json);
            } Else { WriteLog -Log "Saw $FailedLogins Failed Logins and Needed $(($LastEmailAlert.Failed_Count + $Config.AlertThreshold)) to send an alert. (2)"; }
        } Else { WriteLog -Log "Saw $FailedLogins Failed Logins and Needed $(($Config.AlertThreshold)) to send an alert. (1)"; }
    } Catch { WriteLog -Log "[ERROR] Error sending Email Alert." -Data $_; }
}

$EarliestLog = Get-Date -Day 1 -Hour 0 -Minute 0 -Second 0;

If ($Config.CheckMonthBefore) {
    $StartTime = ((Get-Date -Date $EarliestLog).AddMonths(-1));
    $EndTime = (Get-Date -Date $EarliestLog -Hour 23 -Minute 59 -Second 59).AddDays(-1);
    FetchAuth -Earliest $StartTime -Latest $EndTime -FileDate (Get-Date -Date $EndTime -UFormat "%Y-%b") -AlertLimit 20;
}

FetchAuth -Earliest $EarliestLog -Latest (Get-Date) -FileDate (Get-Date -UFormat "%Y-%b");
Write-Host "Script Completed in $([math]::Round((New-TimeSpan -Start $ScriptStart -End (Get-Date)).TotalSeconds, 1)) Seconds. Random Offset was $RandomNumber Seconds.";

WriteLog -Log "----------------------------------------- End ----------------------------------------";

Exit 0;

