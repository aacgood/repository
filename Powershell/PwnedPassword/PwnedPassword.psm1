Function Test-PwnedPassword{
<#
.SYNOPSIS
Check a password against the Troy Hunt Pwned Passwords service

.DESCRIPTION
Check a supplied password against over 500 Million known to be previously exposed in data breaches.


.PARAMETER passwords
Enter a single password or a series of passwords in a comma delimited list

.PARAMETER proxy
Pass a proxy server parameter to use with invoke-webrequest

.INPUTS
Plain text password or passwords

.OUTPUTS
Password exposure status as per Pwned Password service.
ie: WARNING: Password 'Password' has been exposed 'n' times

.NOTES
This script converts a supplied password into a SHA1 hash which then passes the first 5 characters of this hash over the the Pwned Password service.
All matching hashes are retreived and then compared against the full SHA1 hash of the password.  At no time is the plain text password transmitted.
Even if the suppied password returns back OK, this only means that it has not been previously exposed in a data breach.  It does not guarantee the password is actually strong or any good.

.EXAMPLE
Test-PwnedPassword -password "Password1"
Pass a single password for checking

.EXAMPLE
Test-PwnedPassword -passwords "Password1","Password2" -proxy Proxy:PORT
Pass multiple passwords for checking using a custom proxy server

.EXAMPLE
"Password1","Password2" | Test-PwnedPassword
Pass multiple passwords for checking via pipeline

.EXAMPLE
Get-Content PasswordLists.txt | Test-PwnedPassword
Read the contents of a file and perform a check of each via the pipeline


.LINK
Troy Hunt Pwned Passwords
https://haveibeenpwned.com/Passwords
https://haveibeenpwned.com/API/v2#PwnedPasswords

Code for getting the hash of a string loosely based from the following code snippet
https://gallery.technet.microsoft.com/scriptcenter/Get-StringHash-aa843f71

#>


    [CmdletBinding()]

    Param(
        [Parameter(ValueFromPipeline=$True, Mandatory=$true)]
        [alias("password")]
        [string[]]$passwords,
        [string]$proxy
    )


    BEGIN{

        #Ignore Certificate issues
        add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@

        #[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

    }


    PROCESS{

        foreach($password in $passwords){

            $StringBuilder = New-Object System.Text.StringBuilder

            [System.Security.Cryptography.HashAlgorithm]::Create('SHA1').ComputeHash([System.Text.Encoding]::UTF8.GetBytes($password)) | ForEach-Object {
                [Void]$StringBuilder.Append($_.ToString("x2"))
            }

            Write-verbose "$password : $StringBuilder" #.ToString()"

            #Grab the first 5 characters of the hash and mash it together to pass over to the API
            $url = 'https://api.pwnedpasswords.com/range/'+([string]$StringBuilder).Substring(0,5)

            Try{

                if($proxy){
                $results = Invoke-WebRequest -Uri $url -Proxy $proxy -ProxyUseDefaultCredentials  -ErrorAction Stop
            }

            else{
                $results = Invoke-WebRequest -Uri $url -ErrorAction Stop   #Returns as <LAST 35 CHAR OF HASH>:<COUNT>
            }

                }

            Catch{
                Write-Output "An error occured.  Use -verbose for more information"
                write-verbose $_.Exception
                Write-Verbose "Error connecting to proxy server $proxy.  Quitting!"
                break
            }



            $exposed=$false
            $returncount = ($results.Content -split("`n")).Count
            Write-Verbose "$returncount Hashs returned from API"

            #Many hases are returned, compare that list against the supplied password's hash
            foreach($result in $results.Content -split("`n")){


                #Add the first 5 of the supplied passwords hash and mash it together with the returned hash to compare it.
                $a = ([string]$StringBuilder).Substring(0,5) + $result.split(":")[0]

                #Write-verbose "Password hash  : $StringBuilder"
                write-Verbose "Result from API: $a"

                if(Compare-Object ([string]$StringBuilder) $a -IncludeEqual -ExcludeDifferent){
                    $exposed=$true


                    [int]$exposedcount=$result.split(":")[1]
                    [string]$exposedcount = '{0:N0}' -f $exposedcount

                    Write-Verbose "Match found!"
                    break
                }

                else{
                    $exposed=$false
                }

            }

            if($exposed){
                Write-Warning "Password '$password' has been exposed $exposedcount times"
            }

            Else{
                Write-Output "Password '$password' has not been exposed."
            }


        }

    }

    END{}

}
