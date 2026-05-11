function adGrab {

    $currentdate = Get-Date
    $numberofdays = -5

    #Last logon date is set to 5 days prior to current date. Users are expected to be logging in at least once within 5 days except for vacation, illness, etc.
    $setDate = $currentdate.AddDays($numberofdays)
    Write-Host "Latest date set to $setDate" -ForegroundColor Cyan

    #Get enabled computers who have logged on within the last 5 days
    $ldap = try {Write-Host "Attempting LDAP Query..." -ForegroundColor Cyan ; Get-ADComputer -Filter "Enabled -eq 'True'" -properties LastLogonDate | 
    Where-Object { $_.LastLogonDate -ge $setDate } | Sort-Object Name | Select-Object -ExpandProperty Name} catch {Write-Host "LDAP query failed" -ForegroundColor Red ; exit 1}

    #Return list of users
    return $ldap
}

function ssToken {
    
    #Set TLS to 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $username = "<redacted>" #API user in Secret Server.
    $uri = "<redacted SS url>" #Secret Server API token URL.
    $body = @{
        grant_type = 'password'
        username   = $username
        password   = "$env:<redacted>" #Store creds as local user environment variable.
    }
    <#
    HTTP Post call to Secret Server API. Expand access token response into token variable.
    #>
    $response = invoke-restmethod -method post -uri $uri -body $body -headers $null
    $token = $response | Select-Object -ExpandProperty access_token
    <#
    Set authorization type to token. Set URL to the specific secret ID. HTTP Get call. Store expanded username and password values into respective variables.
    #>
    $header = @{ "Authorization" = "Bearer $token" }
    $pwsurl = "<redacted secret url>" #API URL for S1 api secret.
    $response = Invoke-Restmethod -Method GET -Uri $pwsurl -Header $header
    $s1Key = $response.items | Where-Object { $_.fieldname -eq "Password" } | Select-Object -ExpandProperty itemvalue

    #Return sentinelone api key
    return $s1Key
}

function s1Grab {

    #Call api key retrieval function
    $s1Key = ssToken
    $site = "https://usea1-s1sy.sentinelone.net/web/api/v2.1"

    #Set cursor to blank to set index at first object
    $curs = ""
    $headers = @{'Authorization' = "apiToken $s1Key"}
    
    #Maximum reliable query size
    $params = @{limit = 1000}
    $final = @()

    #Rerun the query until next cursor does not appear, indicating there is no next page
    do {
        try {Write-Host "Attemping SentinelOne query" -ForegroundColor Cyan ; $resp = Invoke-RestMethod -Uri "$site/agents?cursor=$curs" -Headers $headers -body $params} catch {Write-Host "Failed to perform S1 query"}
        $curs = $resp.pagination.nextCursor
        $final += $resp.data.computername
    } While ($resp.pagination.nextCursor)

    #Return S1 inventory
    return $final
}

#Set lists
$ldap = adGrab
$ref = s1Grab

#Output only objects appear in AD but not S1
$adComp = Compare-Object ($ldap) ($ref) -IncludeEqual | Where-Object {$_.sideIndicator -eq "<="}
$adComp = $adComp | Select-Object InputObject

#Get exclusion list
$exclusion = Get-Content "<redacted>"
$adFinal = Compare-Object $adComp.InputObject $exclusion | Where-Object {$_.sideIndicator -eq "<="} | Select-Object -ExpandProperty Inputobject

#My own regex exclusion list
$adFinal = $adFinal | Where-Object {$_ -NotMatch <redacted>}

#Write out comparison
$adFinal | Out-File "<redacted>"

function yubiSecret {

    #do/while loop in case yubikey is not inserted
    do {
        #Calculates hash of yubikey secret for user
        try { $secret = ykman otp calculate 2 (
            [System.BitConverter]::ToString(
                [Text.Encoding]::UTF8.GetBytes("username")
            ) -replace '-',''
        )
        } catch {Write-Host "Yubikey not inserted. Please insert and try again."}
    } while (!$secret)

    $securePass = ConvertTo-SecureString $secret -AsPlainText -Force

    #Create credential object for later
    $cred = New-Object System.Management.Automation.PSCredential("domain\user", $securePass)

    #Return credential object
    return $cred
}

function s1InstallTest {

    #This is an array of all common/useful installation error codes
    $s1Table = @{
        100 = "The uninstall of the previous Agent succeeded. Reboot the endpoint to continue with the installation of the new Agent."
        101 = "Reboot is required to continue with the installation."
        103 = "Reboot is required to uninstall the previous Agent and install the new Agent."
        104 = "Reboot is already required by a previous run of the installer."
        200 = "Local Uninstall	Pending User Action	Uninstall is pending on reboot"
        205 = "Installation/Upgrade aborted	Aborted by the user (from the endpoint)."
        206 = "Installation/Upgrade canceled	Handled by command line parser."
        1000 = "An Agent with the same or higher version is already installed on the endpoint."
        1001 = "The version you are trying to downgrade to is too old."
        1002 = "Installation or upgrade canceled. Another installer is already running.	Wait for the previous running to finish."
        1003 = "Installation or upgrade canceled. Another MSI installer is already running.	Finish the other MSI installer."
        1004 = "Upgrade canceled. The arguments given to the Installer (using -a or -- installer arguments) are invalid."
        1005 = "Upgrade Canceled, the passphrase provided is invalid."
        1009 = "Windows Task Scheduler folders \Sentinel and/or \SentinelOne are inaccessible."
        2000 = "General failure. Logs and diagnostic data will help you understand this issue, and will be sent automatically to the SentinelOne Cloud."
        2001 = "Installation failed	Upgrade failed. Cannot proceed with the uninstall and re-install."
        2002 = "Installation failed	Installation failed or upgrade failed. The previous Agent was uninstalled but the installation of the new Agent failed."
        2003 = "Installation failed	Failed to uninstall the old Agent."
        2004 = "Installation failed	Retry in Safe Mode.	If you ran the tool without a passphrase (-k) , rerun the tool with the passphrase."
        2005 = "Installation failed	Upgrade authentication error. Failed to get upgrade approval from the Management."
        2006 = "Installation failed	Configuration not found. Unable to proceed with the upgrade."
        2007 = "Installation failed - unexpected error	The upgrade failed. The installer faced an unexpected error. Cannot proceed with the uninstall and re-install."
        2008 = "Installation failed	Missing site token.	Try again with the site token. From the command line, add the parameter -t <site_token>."
        2009 = "Installation failed	Failed to retrieve the Agent UID.	Upgrade the Agent again with the parameter --dont_preserve_agent_uid or contact Support."
        2010 = "Interactive desktop required. Run the upgrade in Quiet mode. Upgrade the Agent again with the parameter -q or --qn."
        2011 = "Installation failed	The installer is not signed correctly."
        2012 = "Installation failed	Could not determine the currently installed Agent version."
        2013 = "Installation failed	Insufficient system resources."
        2014 = "Installation failed	Extract resources general failure."
        2015 = "Installation failed	System requirements not met or WMI database invalid.."
        2016 = "Installation failed	Microsoft KB2533623 is not installed."
        2017 = "Installation failed	Failed to load DLLs safely."
        2018 = "Installation failed	Downgrade failed."
        2019 = "Installation failed	Upgrade authentication error. Failed to get upgrade approval from the Management."
        2020 = "Installation failed	Not enough space on the system drive."
        2021 = "Installation failed	Upgrade authentication error. Failed to get upgrade approval from the Management."
        2022 = "Installation failed	Unable to create an App Container."
        2023 = "Installation failed	Not enough space on the system drive."
        2024 = "Upgrade failed	Cannot open signed message file."
        2025 = "Upgrade failed	Offline signed message authentication error."
        2026 = "Installation failed	ISAPI filter removal process failed."
        2027 = "The Agent was installed and is in Disabled mode."
        2028 = "The Agent was upgraded and the new Agent is in Disabled mode."
        2029 = "Failed to create a working directory under %WINDIR%\Temp."
        2030 = "The installer failed to open one of the files under its own working directory."
        2031 = "Upgrade aborted	Windows Task Scheduler folders \Sentinel and/or \SentinelOne are inaccessible and could not be removed automatically."
        2032 = "The SentinelOne Installer log could not be opened."
        2034 = "Management connectivity check failed"
        2035 = "Third-party software blocked the ELAM driver, or the OS has outdated root certificates."
        2036 = "SentinelInstallerDriver failed to load.	Reboot the endpoint and try again."
        2037 = "Installer driver connection failed.	Upgrade canceled. Could not communicate with installer driver."
        2038 = "Another installer driver is already running. The SentinelInstallerDriver detected another installer driver already running which it could not unload."
    }

    #Instantiate empty array to store ps custom objects later
    $scan = @()

    #Call back yubikey credential from earlier
    $usr = yubiSecret

    #For each machine in the list
    foreach ($mach in $adFinal) {

        #See if it is alive
        try { $live = Test-Connection $mach -Count 1 -Quiet } 
        catch {
            #There is a difference between tnc failing, and the host not responding
            $status = "Ping Failed" 
            $s1Inst = "Install not attempted"
            $scan += [PSCustomObject] @{
                Computer = $mach
                Status = $status
                S1_Install = $s1Inst
            }
            continue
        }
        if (!$live) {
            $status = "Host is not alive"
            $s1Inst = "Install not attempted"
        }
        else {
            $status = "Host Alive"
            try {
                #Create ps session with machine
                $s = New-PSSession -ComputerName "$mach" -Credential $usr

                #Try copying install file from network share to remote machine local folder
                try { Copy-Item -Path '<redacted>' -Destination "C:\Temp" -ToSession $s }
                catch {Write-Host "Copy S1 file failed with error: $($_.Exception.Message)." ; $a = Read-Host "If this is because the path does not exist, please type 1 to create the folder and try again or 0 to break and move on."}

                #If user enters 1 to try again
                if ($a -eq "1") {
                    #Make directory since it didn't exist and try copy again
                    try {Invoke-Command -ComputerName "$mach" -Credential $usr -ScriptBlock { mkdir C:\Temp ; Copy-Item -Path '<redacted>' -Destination "C:\Temp" -ToSession $s}}
                    catch {Write-Host "Retry failed with error: $($_.Exception.Message)" ; break}
                #If the error is different
                } elseif ($a -eq "0") {
                    Write-Host "Okay. Continuing." ; break
                }

                #Kick off the installation. If it hangs for longer than 10m, kill it and report
                $t = Invoke-Command -ComputerName "$mach" -Credential $usr -ScriptBlock { 
                    $proc = Start-Process "C:\Temp\SentinelOneInstaller.exe" -PassThru -Wait -ArgumentList '-t "<site token>" -q'
                    if (!$proc.WaitForExit(600000)) {$proc.Kill() ; return [PSCustomObject]@{ExitCode = 1; TimedOut = $true}}
                    return [PSCustomObject]@{ ExitCode = $proc.ExitCode }
                }

                #Read the exit code
                $exit = $t.ExitCode

                #If the exit code is non-zero (bad) and the code is found in our array of codes
                if ($exit -ne 0 -and $s1Table[$exit]) { 
                    $s1Inst = $s1Table[$exit]
                    $status = "Install failed. See S1_Install for error."
                }

                #If the code was set to 1 (manually set due to timeout)
                elseif ($exit -eq 1) {
                    $s1Inst = "N/A"
                    $status = "Install timed out."
                }
                else {
                    $s1Inst = "Success"
                    $status = "Installed"
                }
            } catch {Write-Host "SentinelOne Install failed: $($_.Exception.Message)" ; $s1Inst = "$($_.Exception.Message)" ; $status = "RPC Command failed."}

        }

        #Store results into ps custom object to be readable
        $scan += [PSCustomObject] @{
            Computer = $mach
            Status = $status
            S1_Install = $s1Inst
        }
    }
    return $scan
}

#Output to file
$scan = s1InstallTest
$scan | Out-File "C:\Temp\s1Scan.txt"
