'''
MIT License

Copyright (c) 2021 EDF

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''
$ErrorActionPreference = "SilentlyContinue"
Stop-Transcript | out-null
$ErrorActionPreference = "Continue"

$operationName = "TESTS"
$username = "FTP_ACCOUNT"
$password = "FTP_PASSWORD"
$taskname = "spiced" #no space
$zipfile = 'spiced.zip'
$dirname = $zipfile.Split('.')[0]
$exename = 'orc.exe'
$execonfig = 'ORC.xml'
$url = 'http://192.168.1.1/ORC/'
$ftpServer = "192.168.1.1:21"
$localdir = 'C:\Windows\Temp\'
$hostname = $env:COMPUTERNAME
$dest = @('email@dre.ss')
$XPath = '/dfir-orc/key'
$disk = Get-WmiObject Win32_LogicalDisk  -Filter "DeviceID='C:'"
$smtpServer = 'smtp.server.domain.tld'
$smtpSender = 'noreply@domain.tld'

#Creating logoutput and filenames
$LogFileTemp = $localdir + (Get-Date -UFormat "%d-%m-%Y-") + "run.log" #temporary log due to the cleaning of previous execution
$LogFile = $localdir + $dirname + "\" + (Get-Date -UFormat "%d-%m-%Y-") + $hostname + "-run.log" #Moved here at the end of the script

Function Write-Log {
    param (
        [Parameter(Mandatory = $True)]
        [array]$LogOutput,
        [Parameter(Mandatory = $True)]
        [string]$Path
    )
    $currentDate = (Get-Date -UFormat "%d-%m-%Y")
    $currentTime = (Get-Date -UFormat "%T")
    $logOutput = $logOutput -join (" ")
    "[$currentDate $currentTime] $logOutput" | Out-File $Path -Append
}

Function Error-Handler {
    $ErrorMessage = $_.Exception.Message
    $ErrorType = $_.exception.GetType().fullname
    Write-Log -LogOutput "Error Details: $ErrorType-$ErrorMessage" -Path $LogFileTemp
    write-host $_.Exception.ErrorRecord
    write-host $_.ScriptStackTrace
}
if (Test-Path $LogFileTemp) {
    Move-Item -Path $LogFileTemp -Destination $LogFile
}

#Checks if there is a scheduled task already running 
try {
    if ([System.Environment]::OSVersion.Version.Major -eq 10) {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -match "$taskname\w*" }
        if ($tasks) {
            foreach ($task in $tasks) {
                if (($task.State -eq 'Running' -or $task.State -eq 'Queued' -or $task.State -eq 'En cours') -and ($task.TaskName -eq $taskname)) {
                    Write-Log -LogOutput "There is already a task. $($task.Taskname):$($task.State)" -Path $LogFileTemp
                    Move-Item -Path $LogFileTemp -Destination $LogFile
                    Write-Host "Task already running or in queue"
                    exit 
                    
                }
            
                else {
                    Write-Log -LogOutput "Task deleted, $($task.TaskName):$($task.State)" -Path $LogFileTemp
                    Unregister-ScheduledTask -TaskName "$($task.Taskname)" -Confirm:$false
                }
                
            }
            
        }
        
    }
    #Windows 7
    else {
        #Use of regex to access task fields
        $tasks = Invoke-Expression ('C:\Windows\System32\schtasks.exe /Query ')  | Select-String "^(?<Taskname>$taskname\w+)\s+(?<Date>\d\d\/\d\d\/\d{4}\s+\d\d:\d\d:\d\d)\s+(?<Status>.+\b)"  
        if ($tasks) {
            foreach ($task in $tasks) {
                $name = $task.Matches[0].Groups['Taskname'].Value
                $status = $task.Matches[0].Groups['Status'].Value
                Write-Log -LogOutput "There is already a task. $name : $status" -Path $LogFileTemp
        
                if ($status -eq 'Runing' -or $status -eq 'Queued' -or $status -eq 'En cours' -and $name -eq $taskname) {
                   
                    Write-Log -LogOutput "There is already a task. $name : $status" -Path $LogFileTemp
                    Move-Item -Path $LogFileTemp -Destination $LogFile
                    Write-Host "Task already running or in queue"
                    exit
                }
        
                else {
                    Invoke-Expression ('schtasks.exe /Delete /TN "' + $name + '" /F') 
                    Write-Host("Task successfuly removed")
                    Write-Log -LogOutput "Task $name successfuly removed" -Path $LogFileTemp
                }
            }
        }
    }
        
        
}

catch {
    Error-Handler
}
 
# Sends via email the logs of the previous execution
try {
    Write-Log -LogOutput "Sending mail" -Path $LogFileTemp
    $logfiles = Get-ChildItem -Name *.log -Path $localdir$taskname | Select-Object -Property @{ n = 'Fullname'; e = { Convert-Path $_.PSPath } }
    $tab = @()
    if ($logfiles) {
        foreach ($file in $logfiles) {
            $tab += $file.Fullname
        }
    }
   
    if ($tab.length -ge 1) {
        Send-MailMessage -From "$smtpSender" -To $dest -Subject "OPERATION_$operationName - $taskname gathering previous run log files on $hostname" -Attachments $tab -Body "Here are the previous run log files gathered on $hostname" -SmtpServer "$smtpServer" -ErrorAction SilentlyContinue
    }
    else {
        Send-MailMessage -From "$smtpSender" -To $dest -Subject "OPERATION_$operationName - $taskname gathering previous run log files on $hostname" -Body "Here are the previous run log files gathered on $hostname" -SmtpServer "$smtpServer" -ErrorAction SilentlyContinue 
    }
}

catch {
    Error-Handler
}

#Removes the files of the previous execution (if any)
try {
    Write-Log -LogOutput "Cleaning the folder" -Path $LogFileTemp
    if (Test-Path $localdir$taskname){
        Invoke-Expression ("C:\Windows\System32\cmd.exe /c rmdir /S /Q $localdir$taskname")
    }
    
    $FileName = "$localdir$zipfile"
    if (Test-Path $FileName) {
        Remove-Item $FileName
    }
}

catch {
    Error-Handler
}

#Preparing dfir-orc
try {

    if ([System.Environment]::OSVersion.Version.Major -eq 10) {
        
        #Download ORC.zip
        #If you don't have authentification on the server you can remove everything concerning credentials
        Write-Log -LogOutput "Downloading zip from $url$zipfile" -Path $LogFileTemp
        $webclient = new-object System.Net.WebClient
        $credCache = new-object System.Net.CredentialCache
        $creds = new-object System.Net.NetworkCredential("$username","$password")
        $credCache.Add($source, "Basic", $creds)
        $webclient.Credentials = $credCache
        $webclient.DownloadFile("$url$zipfile", "$localdir$zipfile")
    
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        Write-Log -LogOutput "Decompressing" -Path $LogFileTemp
        [System.IO.Compression.ZipFile]::ExtractToDirectory(($localdir + $zipfile), $localdir)

        #Checking if the disk has sufficient space (especially useful if making a RAM dump)
        $ram = Get-WmiObject win32_physicalmemory 
        #Checks in the .XML config file for DFIR-ORC if there is a RAM dump
        if ( Select-Xml -Path $localdir$dirname"\$execonfig" -XPath $XPath  | ForEach-Object { $_.Node.InnerXml -Match "GetRam_dmp" }) {
            if (($ram.Capacity + 0, 1 * $ram.Capacity) -gt $disk.FreeSpace) {
                Write-Log -LogOutput "Insuficient space disk : $($disk.FreeSpace/ 1GB) GB" -Path $LogFileTemp
                exit
            }
        }
   
        elseif ($disk.FreeSpace -le 1000000000  ) {
            Write-Log -LogOutput "Insuficient space disk : $($disk.FreeSpace/ 1GB) GB" -Path $LogFileTemp
            exit
         
        }
        Write-Log -LogOutput "There is enough Space on the disk " -Path $LogFileTemp
        Write-Log -LogOutput "Available space : $($disk.FreeSpace/ 1GB) GB"  -Path $LogFileTemp
    }

    #Windows 7 
    else {
            
        #Download and extracting 
        Write-Log -LogOutput "Downloading and decompressing file from $url$zipfile" -Path $LogFileTemp
        
        $webclient = new-object System.Net.WebClient
        $credCache = new-object System.Net.CredentialCache
        $creds = new-object System.Net.NetworkCredential("$username","$password")
        $credCache.Add($source, "Basic", $creds)
        $webclient.Credentials = $credCache
        $webclient.DownloadFile("$url$zipfile", "$localdir$zipfile")

        $shell_app = new-object -com shell.application
        $filename = $FileName 
        $zip_file = $shell_app.namespace($FileName)
        $destination = $shell_app.namespace($localdir)
        $destination.Copyhere($zip_file.items(), 0x14)


        #Checking if the disk has sufficient space (especially useful if making a RAM dump)
        $ram = (Get-WmiObject Win32_ComputerSystem).totalphysicalmemory
        #Checks in the .XML config file for DFIR-ORC if there is a RAM dump
        if ( Select-Xml -Path $localdir$dirname"\$execonfig" -XPath $XPath  | ForEach-Object { $_.Node.InnerXml -Match "GetRam_dmp" }) {
            if (($ram + 0, 1 * $ram) -ge $disk.FreeSpace) {
                Write-Log -LogOutput "Insuficient space disk : $($disk.FreeSpace/ 1GB) GB" -Path $LogFileTemp
                throw "Error: Disk space is insuficient"
            }
        }
     
        elseif ($disk.FreeSpace -le 1000000000  ) {
            Write-Log -LogOutput "Insuficient space disk : $($disk.FreeSpace/ 1GB) GB" -Path $LogFileTemp
            throw "Error: Disk space is insuficient"
           
        }
        Write-Log -LogOutput "There is enough Space on the disk " -Path $LogFileTemp
        Write-Log -LogOutput "Available space : $($disk.FreeSpace/ 1GB) GB" -Path $LogFileTemp
            

    
    }
}
    
catch {
    Error-Handler
}


try {
    Write-Log -LogOutput "Creating task $taskname" -Path $LogFileTemp
 
    # /SD 05/02/2021 /ED 31/03/2025 
    # Creation the scheduled task for ORC
    Write-Host ('C:\Windows\System32\schtasks.exe /Create /SC DAILY /SD 05/02/2021 /ED 31/03/2025 /F /TN "' + "$taskname" + '" /RU system /TR ' + ("$localdir" + "$dirname\$exename"))
    Invoke-Expression ('C:\Windows\System32\schtasks.exe /Create /SC DAILY /SD 05/02/2021 /ED 31/03/2025 /F /TN "' + "$taskname" + '" /RU system /TR ' + ("$localdir" + "$dirname\$exename"))
    Invoke-Expression ('C:\Windows\System32\schtasks.exe /Query /TN "' + "$taskname" + '"')
    Invoke-Expression ('C:\Windows\System32\schtasks.exe /Run /TN "' + "$taskname" + '"')
    
}
 
catch {
    Error-Handler
}
 
Start-Sleep 60
$timeout = 3600 # seconds. Depends heavily on the orc configuration. It can easily last beyond 1h if you make a heavy configuration
$starttime = Get-Date
$now = Get-Date
$delta = New-TimeSpan -Start $starttime -End $now #Elapsed time
 
try {
    if ([System.Environment]::OSVersion.Version.Major -eq 10) {

        #Wait for task to end . Goes on until timeout reached or task ended

        while (((Get-ScheduledTask -TaskName "$taskname").State -ne 'Ready') -and ($delta.Seconds -lt $timeout)) {
            $status = (Get-ScheduledTask -TaskName "$taskname").State
            $now = Get-Date
            $delta = New-TimeSpan -Start $starttime -End $now
            write-host "Waiting task to  complete, status : $status, elapsed time = $delta"
            Write-Log -LogOutput "Task is running... Status : $status, elapsed time = $delta" -Path $LogFileTemp
            
            Start-Sleep 60  
        }
        if ($delta.Seconds -ge $timeout) {
            Write-Log -LogOutput "Task timed out, $taskname : $status" -Path $LogFileTemp
            Write-Host "Task timed out"
        }
        else {
            Write-Log -LogOutput "Task $taskname Completed" -Path $LogFileTemp
            Write-Host "Task completed"
        }
        
    }
    else {
        
        #Wait for task to end . Goes on until timeout reached or task ended
        #Use of regex to get the task appropriate field
        $task = Invoke-Expression ('C:\Windows\System32\schtasks.exe /Query ')  | Select-String "^(?<Taskname>$([regex]::escape($taskname)))\s+(?<Date>\d\d\/\d\d\/\d{4}\s+\d\d:\d\d:\d\d)\s+(?<Status>.+\b)"  
        $taskinfo = $task.Matches[0].Groups['Status'].Value
        while ( -not ($taskinfo -match 'Prêt' -or $taskinfo -match 'Ready') -and ($delta.Seconds -lt $timeout)) {
            
            $now = Get-Date
            $delta = New-TimeSpan -Start $starttime -End $now
            write-host "Waiting task to  complete, status : $taskinfo, elapsed time = $delta"
            Write-Log -LogOutput "Task is running... Status : $taskinfo, elapsed time = $delta" -Path $LogFileTemp
            Start-Sleep 60
            $task = Invoke-Expression ('C:\Windows\System32\schtasks.exe /Query ')  | Select-String "^(?<Taskname>$([regex]::escape($taskname)))\s+(?<Date>\d\d\/\d\d\/\d{4}\s+\d\d:\d\d:\d\d)\s+(?<Status>.+\b)"  
            $taskinfo = $task.Matches[0].Groups['Status'].Value 
        }
        if ($delta.Seconds -ge $timeout) {
            Write-Log -LogOutput "Task timed out, $taskname : $taskinfo" -Path $LogFileTemp
            Write-Host "Task timed out"
        }
        else {
            Write-Host "Task completed"
            Write-Log -LogOutput "Task $taskname Completed" -Path $LogFileTemp
        }
    }
}
catch {
    Error-Handler
}
 

# Delete the task wether it ended properly or timed out
finally {
    try {
        if ([System.Environment]::OSVersion.Version.Major -eq 10) {
     
            Get-ScheduledTask -TaskName "$taskname" -ErrorAction SilentlyContinue -OutVariable task
            if ($task) {
                Unregister-ScheduledTask -TaskName "$taskname" -Confirm:$false
                Write-Host("Task successfuly removed")
                Write-Log -LogOutput "Task $taskname successfuly removed" -Path $LogFileTemp
            }
           
        }
        else {
            $test = Invoke-Expression ('C:\Windows\System32\schtasks.exe /Query /TN "' + "$taskname" + '"')
            if ($null -ne $test) {
                Invoke-Expression ('schtasks.exe /Delete /TN "' + $taskname + '" /F') 
                Write-Host("Task successfuly removed")
                Write-Log -LogOutput "Task $taskname successfuly removed" -Path $LogFileTemp
     
            }
        }
    }
    catch {
        Error-Handler
    }
}


Write-Log -LogOutput "Starting FTP sending phase" -Path $LogFileTemp
#FTP Certification ignore
try {
    if (-not ([System.Management.Automation.PSTypeName]'CertValidation').Type) {
        Add-Type @"
		using System.Net;
		using System.Net.Security;
		using System.Security.Cryptography.X509Certificates;
		public class CertValidation
		{
			static bool IgnoreValidation(object o, X509Certificate c, X509Chain ch, SslPolicyErrors e) {
				return true;
			}
			public static void Ignore() {
				ServicePointManager.ServerCertificateValidationCallback = IgnoreValidation;
			}
			public static void Restore() {
				ServicePointManager.ServerCertificateValidationCallback = null;
			}
		}
"@
    }
    [CertValidation]::Ignore()
}

catch {
    Error-Handler
}

function New-FtpDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $sourceuri,
        [Parameter(Mandatory = $true)]
        [string]
        $username,
        [Parameter(Mandatory = $true)]
        [string]
        $password
    )
    if ($sourceUri -match '\\$|\\\w+$') { throw 'sourceuri should end with a file name' }
    $ftprequest = [System.Net.FtpWebRequest]::Create($sourceuri);
    $ftprequest.Method = [System.Net.WebRequestMethods+Ftp]::MakeDirectory
    $ftprequest.EnableSsl = $True;
    $ftprequest.UseBinary = $True
    $ftprequest.UsePassive = $True
    $ftprequest.KeepAlive = $True
  
    $ftprequest.Credentials = New-Object System.Net.NetworkCredential($username, $password)
  
    $response = $ftprequest.GetResponse();
  
    Write-Host Upload File Complete, status $response.StatusDescription
  
    $response.Close();
}


Function Send-FTPSFile {
    param (
        [string]$file = $(throw "-file is required"),
        [string]$ftphostpath = $(throw "-ftphostpath is required"),
        [string]$username = $(throw "-username is required"),
        [string]$password = $(throw "-password is required")
    )
    try {
        $f = Get-Item $file
        $req = [System.Net.FtpWebRequest]::Create("ftp://$ftphostpath/" + $f.Name);
        $req.Credentials = New-Object System.Net.NetworkCredential($username, $password);
        $req.Method = [System.Net.WebRequestMethods+Ftp]::UploadFile;
        $req.EnableSsl = $True;
        $req.UseBinary = $True
        $req.UsePassive = $True
        $req.KeepAlive = $True
        $req.ConnectionGroupName = "FTPS$username";

        $fs = new-object IO.FileStream $f.FullName, 'Open', 'Read'
        $ftpStream = $req.GetRequestStream();
        $req.ContentLength = $f.Length;

        Write-Log -LogOutput "Sending $f to $ftphostpath" -Path $LogFileTemp
    }

    catch {
        Error-Handler
    }
    

    try {
        $b = new-object Byte[](10000)

        while ($true) {
            $r = $fs.Read($b, 0, 10000);
            if ($r -eq 0) { break; }
            $ftpStream.Write($b, 0, $r);
        }

    }
    catch {
        Error-Handler
    }
    finally {
        if ($null -ne $fs) { $fs.Dispose(); }
        $ftpStream.Close();    
        $resp = $req.GetResponse();
        $resp.StatusDescription;
        $resp.Close();
    }
}

#Starting FTP upload phase

Write-Log -LogOutput "Creating directory on FTP server" -Path $LogFileTemp

#Creates directory in the ftp server. Each hosts has it's own directory inside the directory of the operation
$ErrorActionPreference = 'SilentlyContinue'
New-FtpDirectory -sourceuri "ftp://$ftpServer/$operationName/" -username $username -password $password
New-FtpDirectory -sourceuri "ftp://$ftpServer/$operationName/$hostname" -username $username -password $password
$ErrorActionPreference = 'Continue'

try {
	
    $client = New-Object System.Net.WebClient

    $client.Credentials = New-Object System.Net.NetworkCredential("$username", "$password")

    # Getting all dfir orc files (.7z) and filtering empty files if they exist 
    $filelist = Get-ChildItem "$localdir$dirname\DFIR-ORC_*" | Where-Object { $_.Length -gt 0kb }
    
    write-host $filelist
    

    Write-Log -LogOutput "File list size = $($filelist.Length) : $filelist, " -Path $LogFileTemp


    Write-Log -LogOutput "Sending files to the FTP server" -Path $LogFileTemp
    #For each files, we send it with ftp
    ForEach ($file in $filelist) { 
        $filename = $file.Name
        write-host $filename
        
        Send-FTPSFile -file "$localdir\$dirname\$filename" -ftphostpath "$ftpServer/$operationName/$hostname/" -username $username -password $password
    }

}

catch {
    Error-Handler
}
#We end the script by moving the logs inside the final folder, send it via ftp. If there has been a problem that prevented the script to reach this point, the logs will be sent by email at the next execution
Write-Log -LogOutput "All files have been sent" -Path $LogFileTemp
Move-Item -Path $LogFileTemp -Destination $LogFile
$finalLog = Get-ChildItem "$localdir$dirname\" | Where-Object { $_.Name -match '(\d\d\-\d\d\-\d{4})\-(\w+)\-run\.log' }
Send-FTPSFile -file "$localdir$dirname\$($finalLog.Name)" -ftphostpath "$ftpServer/$operationName/$hostname/" -username $username -password $password

[CertValidation]::Restore()


Start-Sleep -Seconds 1
