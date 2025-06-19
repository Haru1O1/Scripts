# Ask user for SPNs file path
$spnFilePath = Read-Host "Enter path to SPNs file (comma separated hostnames)"

# Define subnets
$subnets = @(
    "10.1.1.0/24" # add subnets
)

function Test-IpInSubnet {
    param(
        [string]$ip,
        [string[]]$subnets
    )

    foreach ($subnet in $subnets) {
        $parts = $subnet -split '/'
        $net = [IPAddress] $parts[0]
        $maskBits = [int] $parts[1]

        $ipBytes = ([IPAddress]$ip).GetAddressBytes()
        $netBytes = $net.GetAddressBytes()

        $mask = [math]::Pow(2, 32) - [math]::Pow(2, (32 - $maskBits))
        $maskBytes = [BitConverter]::GetBytes([UInt32]$mask)
        if ([BitConverter]::IsLittleEndian) {
            [Array]::Reverse($maskBytes)
        }

        $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)
        $netInt = [BitConverter]::ToUInt32($netBytes, 0)
        $maskInt = [BitConverter]::ToUInt32($maskBytes, 0)

        if (($ipInt -band $maskInt) -eq ($netInt -band $maskInt)) {
            return $true
        }
    }
    return $false
}

# Load SPNs
$content = Get-Content $spnFilePath -Raw
$hostnames = $content -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

if ($hostnames.Count -eq 0) {
    Write-Host "No hostnames found in file."
    exit
}

$matchingIps = @()

foreach ($hostname in $hostnames) {
    try {
        $resolved = Resolve-DnsName -Name $hostname -ErrorAction Stop
        $aRecords = $resolved | Where-Object { $_.Type -eq "A" }

        if ($aRecords.Count -eq 0) {
            Write-Warning "No A records found for $hostname"
            continue
        }

        foreach ($record in $aRecords) {
            $ip = $record.IPAddress.ToString()
            if (Test-IpInSubnet -ip $ip -subnets $subnets) {
                $matchingIps += $ip
            }
        }
    } catch {
        Write-Warning "Could not resolve $hostname"
    }
}

Write-Host "`nFiltered IPs in Subnet(s):"
Write-Host ($matchingIps -join ', ')
Write-Host "`nTotal: $($matchingIps.Count)"
