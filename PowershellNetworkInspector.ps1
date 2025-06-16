function Get-AddressData {

    
    $Addresses = Get-NetTCPConnection -RemoteAddress * -State Established | Where-Object {$_.LocalAddress -notmatch "127.0.0.1"}
    foreach ($address in $Addresses){
        $ProcessName = Get-Process -PID $address.OwningProcess -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName

        if($address.RemoteAddress -notcontains $global:MasterDatabase.Keys){  
            write-host -ForegroundColor Green "Adding Remote Address $($address.RemoteAddress) with process $($ProcessName) to database..."
            $global:MasterDatabase[$address.RemoteAddress] = @{ 
                
                PID = $address.OwningProcess
                Process = $ProcessName 
            
            }
        }
    }
    
   
}

function Get-ProcessHash {

    write-host -ForegroundColor Cyan "`n Adding associated processes to database.. `n"

    foreach ($IPaddress in $global:MasterDatabase.Keys) {
        $ProcessName = $global:MasterDatabase[$IPaddress]["Process"]

        if (-not [string]::IsNullOrEmpty($ProcessName)) {
            $ProcessPath = (Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path -First 1)

            if ($null -ne $ProcessPath) {
                $FileHashObj = Get-FileHash -Path $ProcessPath -ErrorAction SilentlyContinue
                if ($FileHashObj) {
                    $FileHash = $FileHashObj.Hash
                    Write-Host -ForegroundColor Green "Adding process $ProcessName with file hash $FileHash to IP $IPaddress in database..."

                    $global:MasterDatabase[$IPaddress]["FileHash"] = $FileHash
                }
                else {
                    Write-Host -ForegroundColor Yellow "Could not get file hash for process $ProcessName"
                }
            }
            else {
                Write-Host -ForegroundColor Yellow "No executable path found for process $ProcessName"
            }
        }
        else {
            Write-Host -ForegroundColor Yellow "No process name found for IP $IPaddress"
        }
    }
}
function Get-APIKeys {


$APIKeys = @{}


$IPInfoAPIKey = Read-Host "Please enter your IPinfo API key" 
$VirusTotalAPIKey = Read-Host "Please enter your VirusTotal API Key" 
$AbuseIPDBAPIKey = Read-Host "Please enter your AbuseIPDB API Key" 


$APIKeys.add("VirusTotalAPIKey", $VirusTotalAPIKey)
$APIKeys.add("AbuseIPDBAPIKey", $AbuseIPDBAPIKey)
$APIKeys.add("IPinfoAPIKey", $IPInfoAPIKey)

return $APIKeys
}

function Query-AbuseIPDB {

param(
$apikey,    
$IPAddress
)

$uri = "https://api.abuseipdb.com/api/v2/check"
$params = @{
    ipAddress = $IPAddress
    maxAgeInDays = 90  
}

$headers = @{
    Key = $apiKey
}


$response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -Body $params
return $response

}

function Query-VirusTotal{

    param(

    $FileHash,
    $APIKey

    )

$headers=@{}
$headers.Add("accept", "application/json")
$headers.add("x-apikey", "$($APIKey)")
$response = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$($FileHash)" -Method GET -Headers $headers
return $response

}

function Query-IPinfo{
    
    param(
    $APIKey,    
    $IPAddress
    )

    $uri = "https://ipinfo.io/" + $IPAddress + "?token=" + $APIKey 
    $uri
    $response = Invoke-RestMethod -uri $uri
    return $response

}

function Export-Database{

    param(
    $database
    )

    $cwd = Get-Location
    $timestamp = Get-Date -Format o | ForEach-Object { $_ -replace ":", "." }

$json = $database | ConvertTo-Json -Depth 10

try {$json | Out-File -FilePath "$($cwd)\database$($timestamp).json"

write-host -ForegroundColor Green "Database export succeeded $($cwd)\database$($timestamp).json "
}

catch { Write-Host -ForegroundColor Red "Database export failed!"}

}

function Main{

    write-host -ForegroundColor Cyan "     ____  ____ _       ____________  _____ __  __________    __       _   _______________       ______  ____  __ __    _____   _______ ____  ______________________  ____ 
   / __ \/ __ \ |     / / ____/ __ \/ ___// / / / ____/ /   / /      / | / / ____/_  __/ |     / / __ \/ __ \/ //_/   /  _/ | / / ___// __ \/ ____/ ____/_  __/ __ \/ __ \
  / /_/ / / / / | /| / / __/ / /_/ /\__ \/ /_/ / __/ / /   / /      /  |/ / __/   / /  | | /| / / / / / /_/ / ,<      / //  |/ /\__ \/ /_/ / __/ / /     / / / / / / /_/ /
 / ____/ /_/ /| |/ |/ / /___/ _, _/___/ / __  / /___/ /___/ /___   / /|  / /___  / /   | |/ |/ / /_/ / _, _/ /| |   _/ // /|  /___/ / ____/ /___/ /___  / / / /_/ / _, _/ 
/_/    \____/ |__/|__/_____/_/ |_|/____/_/ /_/_____/_____/_____/  /_/ |_/_____/ /_/    |__/|__/\____/_/ |_/_/ |_|  /___/_/ |_//____/_/   /_____/\____/ /_/  \____/_/ |_|  
                                                                                                                                                                        "

    write-host  -ForegroundColor  Cyan "`nWelcome to the Powershell Network Inspector!"

    Start-Sleep 1

    write-host -ForegroundColor Cyan "`nPress any key to begin.."

    [System.Console]::ReadKey($true)

    Write-host -ForegroundColor Cyan "Performing initial enumeration of remote addresses.. `n"

    Start-Sleep 1

$global:MasterDatabase = @{}

$IPDatabase = Get-AddressData
$HashDatabase = Get-ProcessHash

foreach ($Address in $IPDatabase.keys){
    $ProcessName = $IPDatabase[$Address]
    $ProcessHash = $HashDatabase.$ProcessName
    $MasterDatabase[$Address] = @{}
    $MasterDatabase.$Address["ProcessName"] = $Processname
    $MasterDatabase.$Address["ProcessHash"] = $ProcessHash
}

start-sleep 1

Submain

}

function SubMain {


Write-Host -ForegroundColor Cyan "`n Welcome to the Powershell Network Inspector menu! The following commands are available for use:"

write-host -ForegroundColor Yellow "`n Enter-APIkeys (Allows you to enter API keys to query data from threat intelligence platforms)

 Get-IPinfo (Querys IPINFO.net database to gather additional intel on each IP Address)

 Get-IPAbuseInfo (Querys AbuseIPDB database for IP blacklist status)

 Get-VirusTotal (Querys VirusTotals API to check the file hash of the process associated with each IP for indicators of malware)

 Show-Database (Shows current IP connections and gathered data)

 Export-Database (Exports live database to JSON file)
"

$input = read-host "Please enter a command to continue. To exit, enter exit"

if ($input -eq "Enter-APIkeys"){

    $global:APIKeys = Get-APIKeys

    write-host -ForegroundColor Cyan "Thanks for entering API Keys! Returning to main menu.. `n"
    start-sleep 1 
    return SubMain
}

if ($input -eq "Get-IPInfo"){

    write-host "`n"
foreach ($IP in $global:MasterDatabase.Keys){

        $response = Query-IPinfo -APIKey $global:APIKeys."IPinfoAPIKey" -IPAddress $IP
        
        $global:MasterDatabase[$IP]["hostname"] = $response.hostname
        $global:MasterDatabase[$IP]["city"] = $response.city
        $global:MasterDatabase[$IP]["region"] = $response.region
        $global:MasterDatabase[$IP]["country"] = $response.country
        $global:MasterDatabase[$IP]["location"] = $response.loc
        $global:MasterDatabase[$IP]["organization"] = $response.org
        $global:MasterDatabase[$IP]["postal"] = $response.postal
        $global:MasterDatabase[$IP]["timezone"] = $response.timezone
       
    }

    foreach ($IP in $global:MasterDatabase.Keys){

        write-host -ForegroundColor Green "$($IP) is associated with process $($global:MasterDatabase[$IP].Process) is located in $($global:MasterDatabase[$IP].city), $($global:MasterDatabase[$IP].country)  "

    }

    write-host -ForegroundColor Cyan "`nPress any key to return to main menu.."

    [System.Console]::ReadKey($true)

    return submain
}

if ($input -eq "Get-IPAbuseInfo"){

    write-host "`n"
    foreach ($IP in $global:MasterDatabase.Keys){

       
    try {
        $response = Query-AbuseIPDB -apikey $global:APIKeys["AbuseIPDBAPIKey"] -IPAddress $IP
    }
    catch {
        write-host -ForegroundColor Red "An error occured while querying the ABUSEIPDB API"
    }
    
    $global:MasterDatabase[$IP]["abusescore"] = $response.data.abuseConfidenceScore 

    }

    foreach ($IP in $global:MasterDatabase.keys){

        $AbuseScore = $global:MasterDatabase.$IP.abusescore
        $Process = $global:MasterDatabase.$IP.Process
        if ($AbuseScore -gt 0){

            Write-Host -ForegroundColor Red -BackgroundColor Yellow "WARNING: IP Address $IP associated with process $($Process) is in ABUSEIPDB with an Abuse Confidence Score of $AbuseScore "
        }
        else{

            Write-Host -ForegroundColor Green "IP Address $IP associated with process $($Process) is not found in ABUSEIPDB "
        }

    }

    write-host -ForegroundColor Cyan "`nPress any key to return to main menu.."

    [System.Console]::ReadKey($true)
    return submain

}

if ($input -eq "Get-VirusTotal"){

    $counter = 0

    $Hashlist = @()

    foreach ($IP in $global:MasterDatabase.Keys){

        $Hash = $global:MasterDatabase[$IP].FileHash


        $Hashlist += [PSCustomObject]@{
            IP = $IP
            Hash = $Hash
        }

    }



    $Hashlist = $Hashlist | Sort-Object Hash -Unique

    foreach ($item in $Hashlist){

        write-host -ForegroundColor Green "Checking hash $($item.Hash) associated with IP Address $($item.IP) against VirutotalDB"

        try {
        $response = Query-VirusTotal -FileHash $item.Hash -APIKey $APIKeys.VirusTotalAPIKey 
            if ($response.data.attributes.last_analysis_stats.malicious -gt 0){write-host -ForegroundColor red "Hash $($item.Hash) associated with IP Address $($item.IP) is malicious!"}
        $global:MasterDatabase[$item.IP]["VirusTotalResult"] = $response.data.attributes.last_analysis_stats.malicious
        $counter++
        }
        catch{
            write-host "An error occured getting Virustotal report on hash $($item.Hash)"
            write-host "Error: $_"

        }
        
    if ($counter -eq 4){
        write-host -ForegroundColor Cyan "VirusTotal API rate limit of 4 requests/minute limit reached, pausing querying until limit resets (60 seconds)"
        start-sleep 60
        $counter = 0
    }

    
}

   write-host -ForegroundColor Cyan "`nPress any key to return to main menu.."

    [System.Console]::ReadKey($true)
    return submain

}

if ($input -eq "Show-Database"){

    foreach ($IP in $global:MasterDatabase.keys){

        Write-Host -ForegroundColor Yellow "IP Address: $($IP):"
        $global:MasterDatabase[$IP] | Format-List
        

        
    }

    write-host -ForegroundColor Cyan "`nPress any key to return to main menu.."
    [System.Console]::ReadKey($true)
    return submain

}

if ($input -eq "Export-Database"){

    try {Export-Database -database $global:MasterDatabase }
        

    catch{  write-host "database export failed"}

    write-host -ForegroundColor Cyan "`nPress any key to return to main menu.."

    [System.Console]::ReadKey($true)
    return submain
}

if ($input -eq "exit"){

$global:MasterDatabase.Clear()
Clear-Host
}

else {

    write-host -ForegroundColor Red " `n The input invalid. Please try again! `n"
    return SubMain

}
}

Main
