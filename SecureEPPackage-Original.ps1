$submittedFolder = "C:\ECRCPScanSignUITool\OutputInfo\Submitted"
$SecProcessedFiles = "\\SIGNSCANEPCP01\\~EP_Installers\Submitted"
$approvedFolder = "\\SIGNSCANEPCP01\ECRCPScanSignUITool$\OutputInfo\Approved"
$clientSigningTools = "\\devappsecsvs\ClientFileSigningTools\Latest"
$signLogFile = "\\SIGNSCANEPCP01\SignLogFiles"
$uploadSubmittedFolder = "\\hqazrndfs01\upload$\EP Installer\EPUpload\Submitted"
$UploadApprovedFolder = "\\hqazrndfs01\upload$\EP Installer\EPUpload\Output"
$UploadArchiveFolder = "\\hqazrndfs01\upload$\EP Installer\EPUpload\Archive"
#-----------------------------------------------------------------------------------------------------------------------------

Write-Host (Get-Date) ("===================================== START")
#Write-Host (Get-ChildItem $ProcessQueueFolder)
#For each folder in hqazrndfs01 output folder, check to see if it is same as hqazrndfs01 submitted folder.
$uploadPatchFolders = Get-ChildItem "$UploadApprovedFolder" -Directory
$uploadOutputBody += "`nApporved Folder:`n" + ($uploadPatchFolders | Out-String)
Foreach ($uploadPatchFolder in $uploadPatchFolders) {
    $folderName = $uploadPatchFolder.Name
    if($folderName -ne 'Old'){
        if (Test-Path "$uploadPatchFolders\Old\$folderName") {
            Rename-Item -Path "$uploadPatchFolders\Old\$folderName" -NewName "$folderName_$(Get-Date -format "MM.dd.yy-HH.mm.ss")"
        }
    }
    if (Test-Path "$uploadSubmittedFolder\$folderName") {
        if (Test-Path "$uploadApprovedFolder\Old\$folderName") {
            Rename-Item -Path "\\hqazrndfs01\upload$\EP Installer\EPUpload\Output\Old\$folderName" -NewName $folderName_$(Get-Date -format "MM.dd.yy-HH.mm.ss")
        }
        Move-Item -Path "\\hqazrndfs01\upload$\EP Installer\EPUpload\Output\$folderName" "\\hqazrndfs01\upload$\EP Installer\EPUpload\Output\Old"
    }
}
#copy from UploadSubmittedfolder to local submittedfolder for EP processing.
$hasAnySubdir = (Get-ChildItem -Directory "$uploadSubmittedFolder").Count -gt 0
$hasAnyArchiveDir = (Get-ChildItem -Directory "$UploadArchiveFolder").Count -gt 0
if ($hasAnySubdir) {
    Foreach ($uploadSubmittedPatchFolder in (Get-ChildItem $uploadSubmittedFolder)) {
        if($hasAnyArchiveDir){
            foreach ($archivePatchFolder in (Get-ChildItem $UploadArchiveFolder)) {
                $archiveFolderName = $archivePatchFolder.Name
                if ($archivePatchFolder.Name -eq $uploadSubmittedPatchFolder.Name) {
                    Rename-Item -Path "$UploadArchiveFolder\$archiveFolderName" -NewName "$archiveFolderName+'_'+$(Get-Date -format "MM.dd.yy-HH.mm.ss")"
                    Copy-Item $uploadSubmittedFolder\$uploadSubmittedPatchFolder -Destination "$UploadArchiveFolder" -Recurse
                }
            }
        }
        else {
            Copy-Item $uploadSubmittedFolder\$uploadSubmittedPatchFolder -Destination "$UploadArchiveFolder\$uploadSubmittedPatchFolder" -Recurse 
        }
        Copy-Item $uploadSubmittedFolder\$uploadSubmittedPatchFolder -Destination "$submittedFolder\$uploadSubmittedPatchFolder" -Recurse -Force
    }        
}
else {
    return
}
       
#For each folder in Approved folder, check to see if it is same as submitted folder.
#If so, rename the folder in approved, to today's date and time.
$patchFolders = Get-ChildItem "$approvedFolder" -Directory
$outputBody += "`nApporved Folder:`n" + ($patchFolders | Out-String)

Foreach ($patchFolder in $patchFolders) {
    $folderName = $patchFolder.Name
    if (Test-Path "$approvedFolder\Old\$folderName") {
        Rename-Item -Path "$approvedFolder\Old\$folderName" -NewName "$folderName+'_'+$(Get-Date -format "MM.dd.yy-HH.mm.ss")"
    }
    if (Test-Path "$submittedFolder\$folderName") {
        Move-Item -Path "\\SIGNSCANEPCP01\ECRCPScanSignUITool$\OutputInfo\Approved\$folderName" "\\SIGNSCANEPCP01\ECRCPScanSignUITool$\OutputInfo\Approved\Old"
    }
}
function Create-AesManagedObject($key) {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($key.getType().Name -eq "String") {
        $aesManaged.Key = [System.Convert]::FromBase64String($key)
    }
    else {
        $aesManaged.Key = $key
    }
    $aesManaged
}

function Encrypt-String($key, $unencryptedString) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    $aesManaged.Dispose()
    [System.Convert]::ToBase64String($fullData)
}
   
#Get all files from all folders
if (Get-ChildItem -Path "$submittedFolder") {
   
    Set-Location "$submittedFolder"
    foreach ($uploadedFoldername in (Get-ChildItem -Path "C:\ECRCPScanSignUITool\OutputInfo\Submitted" -Directory)) {
        Write-Host $uploadedFoldername
      
        foreach ($file in ( Get-ChildItem -path "$submittedFolder\$uploadedFolderName" -Recurse -File)) {
            $fileExtension = [IO.Path]::GetExtension($file)
            $fileName = [System.IO.Path]::GetFileName("$file")
        
            #Check file signatures
            $sig = (Get-AuthenticodeSignature -FilePath $file.FullName)
            $sigStatus = ($sig.Status).ToString().ToUpper()

            #sign the unsigned ".dll", ".exe", ".ocx", ".msi", ".cab", ".ps1", ".appx", ".vbs", ".cat", ".pyd",".tx
            if ($sigStatus -eq "NOTSIGNED" -and $fileExtension -ne ".bat" -and $fileExtension -ne ".txt" -and $fileExtension -ne ".html" -and $fileExtension -ne ".htm") {
                $path = $file.Directory
                $myFileFull = $file.FullName
                Set-Location "$path"                
                $signCmd = "C:\Utils\clientSigningTools\AspenRemoteSignDigest.exe '$myFileFull' -Log '$signLogFile\$uploadedFoldername\$(Get-Date -Format yyyy-MM-dd).txt' "
                Invoke-Expression $signCmd
            }
            if ($sigStatus -eq "UNKNOWNERROR" -or $sigStatus -eq "invalid") {
        
                if ($fileName -eq "EP.xml") {
                    $EPXmlFile = $file
                }   
                else {
                    $saveFileChecksum = "$submittedFolder\$uploadedFolderName"
                    $xmlFilePath = "$saveFileChecksum\EP.xml"

                    [XML]$xml = Get-Content $xmlFilePath
                    $xml = New-Object -TypeName XML
                    $xml.Load($xmlFilePath)

                    #Check FileCheckSums node existed or Not
                    if ($xml.EP.FileChecksums) {
                        $childExist = $xml.EP.FileCheckSums

                        #Create checksum for the file
                        $fileChecksum = $file | Get-FileHash -Algorithm SHA256
                    
                        #update the the EP.xml file
                        $Name = $fileChecksum.Path.Replace($saveFileChecksum + "\", "")
                        $Hash = $fileChecksum.Hash
                    
                        $xml.SelectNodes($childExist)
                        $newXMLCheckSumElement = $childExist.AppendChild($xml.CreateElement("CheckSum"))
                        $newXMLCheckSumElement.SetAttribute("Name", $Name)
                        $newXMLCheckSumElement.SetAttribute("Hash", $Hash)
                    
                        $xml.Save($xmlFilePath)
                    }
                    #FileCheckSum not existed creates the Child Element
                    else {
                        $child = $xml.CreateElement("FileCheckSums")
                        $xml.DocumentElement.AppendChild($child)
                                
                        #Create checksum for the file
                        $fileChecksum = $file | Get-FileHash -Algorithm SHA256
                              
                        #update the the EP.xml file
                        $Name = $fileChecksum.Path.Replace($saveFileChecksum + "\", "")
                        $Hash = $fileChecksum.Hash
          
                        $xml.SelectNodes($child)
                        $newXMLCheckSumElement = $child.AppendChild($xml.CreateElement("CheckSum"))
                        $newXMLCheckSumElement.SetAttribute("Name", $Name)
                        $newXMLCheckSumElement.SetAttribute("Hash", $Hash)
                        $xml.Save($xmlFilePath)
                    }
                }          
            }
        }
        $fileChecksum = $EPXmlFile | Get-FileHash -Algorithm SHA256
        write-host "$EPXmlFile"
        $Name = $fileChecksum.Path
        $Hash = $fileChecksum.Hash
        $key = "6fd19efce50247488cd9dbf6c4fc2425"
        $encryptedHash = Encrypt-String $key $Hash
        $encryptedHash > "$submittedFolder\$uploadedFoldername\EP_HashFile.txt"

        Write-Host (Get-Date) " Scan & Copying and removing patch files to source - " $uploadedFoldername
        $hasAnySubdir = (Get-ChildItem -Directory "$submittedFolder").Count -gt 0
        if ($hasAnySubdir) {
            #Scan SecuredEP folder using MalwareBytes.
            Set-Location $submittedFolder
            $scanCmd = 'C:\Utils\Scripts\SupportingScripts\ScanPatch.ps1  "'+"$submittedFolder\$uploadedFolderName"+'"'
            $status = Invoke-Expression -command $scanCmd
            Write-Host "Scan completed - $status" -ForegroundColor Green
        
            if ($status) {
                Write-Host (Get-Date) " Copying and removing patch files to source - " $uploadedFoldername
                $folderName = $uploadedFoldername
                if (Test-Path "$approvedFolder\$folderName") {
                    $newname = "$folderName_$(get-date -f yyyy-MM-dd)"
                    Rename-Item "$approvedFolder\$folderName" -NewName $newName
                    #Copy and remove items sourceoutput and source submitted
                    Copy-Item "$submittedFolder\"+$folderName -Destination "\\SIGNSCANEPCP01\ECRCPScanSignUITool$\OutputInfo\Approved\" -Recurse
                    Write-Host (Get-Date) " Clean up completed. Success - " $folderName
                    $scannedPatches += ("$approvedFolder\" + $folderName)
                }
                else {
                    Copy-Item $submittedFolder\$folderName -Destination "\\SIGNSCANEPCP01\ECRCPScanSignUITool$\OutputInfo\Approved\" -Recurse
                    Remove-Item ("$submittedFolder\$uploadedFolderName") -Recurse -Force
                    Write-Host (Get-Date) " Clean up completed. Success - " $uploadedFolderName
                    $scannedPatches += ("$approvedFolder\$uploadedFolderName")
                }
                #check the folder existed in selfextracted exe submitted folder
                $selfpatchFolders = Get-ChildItem "$SecProcessedFiles" -Directory
                $outputBody += "`nselfextracted Submitted Folder:`n" + ($selfpatchFolders | Out-String)
                if ($selfpatchFolders.Count -ge 1) {
                    Foreach ($selfpatchFolder in $selfpatchFolders) {
                        $folderName = $selfpatchFolder.Name

                        if (Test-Path "$SecProcessedFiles\$folderName") {
                            if ($uploadedFolderName.Name -eq $folderName) {
                                Remove-Item ("$SecProcessedFiles\$folderName") -Recurse -Force

                                #RoboCopy "$approvedFolder\$uploadedFoldername" "$SecProcessedFiles\$uploadedFoldername" /e /ns /np /njh /njs /R:2 /W:30 /mir
                                #xcopy "$approvedFolder\$uploadedFoldername" "$SecProcessedFiles\$uploadedFoldername\" /s /d /f /r /h /k /z
                                #Copy-Item $submittedFolder\$uploadedFoldername -Destination "\\SIGNSCANEPCP01\ECRCPScanSignUITool$\OutputInfo\Approved" -Recurse
                                Copy-Item "\\SIGNSCANEPCP01\ECRCPScanSignUITool$\OutputInfo\Approved\$uploadedFoldername" -Destination "\\SIGNSCANEPCP01\\~EP_Installers\Submitted\$uploadedFoldername" -Recurse          
                                write-Host "Successfully file copied for creating the self-extracted EXE"
                            }          
                        }
    
                    }
       
                }
                else {
                    #RoboCopy "$approvedFolder\$uploadedFoldername" "$SecProcessedFiles\$uploadedFoldername" /e /ns /np /njh /njs /R:2 /W:30 /mir
                    #xcopy "$approvedFolder\$uploadedFoldername" "$SecProcessedFiles\$uploadedFoldername\" /s /d /f /r /h /k /z
                    #Copy-Item $submittedFolder\$uploadedFoldername -Destination "\\SIGNSCANEPCP01\ECRCPScanSignUITool$\OutputInfo\Approved" -Recurse
                    Copy-Item "\\SIGNSCANEPCP01\ECRCPScanSignUITool$\OutputInfo\Approved\$uploadedFoldername" -Destination "\\SIGNSCANEPCP01\\~EP_Installers\Submitted\$uploadedFoldername" -Recurse          
                    write-Host "Successfully file copied for creating the self-extracted EXE"
                }
                #Remove the EPfolder from the Upload location
                Remove-Item ("$uploadSubmittedFolder\$uploadedFoldername") -Recurse -Force
            }
            else {
                Write-Host "Failed to Scan $uploadedFolderName"
            }
        }
        else {
            throw "No folder name called '$uploadedFolderName'"
        }
    }
}




              
              
              
              
                 
                  
           

          


          
         
        
         
           
        
  
# SIG # Begin signature block
# MIIoXAYJKoZIhvcNAQcCoIIoTTCCKEkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAxMXtsRT49VoIq
# ysUZ3c0GsDZOvHyLNALsxhRqD6+5O6CCDcgwggawMIIEmKADAgECAhAIrUCyYNKc
# TJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0z
# NjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0
# JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJr
# Q5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhF
# LqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+F
# LEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh
# 3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJ
# wZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQay
# g9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbI
# YViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchAp
# QfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRro
# OBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IB
# WTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+
# YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAED
# MAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql
# +Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFF
# UP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1h
# mYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3Ryw
# YFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5Ubdld
# AhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw
# 8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnP
# LqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatE
# QOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bn
# KD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQji
# WQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbq
# yK+p/pQd52MbOoZWeE4wggcQMIIE+KADAgECAhABCK5JZAVcFl4jBLHic4jDMA0G
# CSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjMwMzA5MDAwMDAwWhcNMjQwMzA3
# MjM1OTU5WjCBlzELMAkGA1UEBhMCVVMxFjAUBgNVBAgTDU1hc3NhY2h1c2V0dHMx
# EDAOBgNVBAcTB0JlZGZvcmQxHjAcBgNVBAoTFUFzcGVuVGVjaCBDb3Jwb3JhdGlv
# bjEeMBwGA1UECxMVUHJvZHVjdCBTZWN1cml0eSBUZWFtMR4wHAYDVQQDExVBc3Bl
# blRlY2ggQ29ycG9yYXRpb24wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB
# gQCrmPvnB6PVWFnPNY/xPygOmlWaHpRYsWCd348hDHzUe4Zt4M05vcju3OIEN9Nf
# rEeSdWGKwDnDwXhC4Ad32GVpHd7A0yUOiga4ZReZ1iDKCtN1VaMqg2e/eXxFm3tC
# UviCNSAzRLQKlIF3zmDqb+xRvfc23e58jyOGGkkQDd8q44gmfqKpAZGunlQ9RRw2
# 9/FgLtIo6Z/aF+zLxWhJvuuAqre/so1YGBwAF7k/kZCvS5bHSe4viYUoFST72/Oh
# teUSclKfntgpDbdRLb1T82YStCYYKoJWYbsnN4BL2z+7lKi5ipE6HNycS/iApXGO
# lhvbNi12S2h/+nKH8ZD+f/oy44u9qJs8Bdjxou/VplR6cWpDKNxSEJCpxobu3w/c
# KUsx+LZyWWtU90hGUeUwXvsm2NY1uXsBPyYto4o0EmlTdqxgqsAxNFKQ7U+cqKH6
# 9sRQXBY0mh63BYnoakFEvYCjBbcu2tfHRhmO+mUQK2WgTmV5Qb08mgFCtFFdfw3G
# 6zkCAwEAAaOCAgMwggH/MB8GA1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5C
# MB0GA1UdDgQWBBT/Ej78IwxL9MYx1p0hA2uvMwGg8zAOBgNVHQ8BAf8EBAMCB4Aw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwgbUGA1UdHwSBrTCBqjBToFGgT4ZNaHR0cDov
# L2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdS
# U0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwU6BRoE+GTWh0dHA6Ly9jcmw0LmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4
# NDIwMjFDQTEuY3JsMD4GA1UdIAQ3MDUwMwYGZ4EMAQQBMCkwJwYIKwYBBQUHAgEW
# G2h0dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCBlAYIKwYBBQUHAQEEgYcwgYQw
# JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcw
# AoZQaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0
# Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcnQwCQYDVR0TBAIwADAN
# BgkqhkiG9w0BAQsFAAOCAgEAKIUyTWNth4BHUjHHpPzO93KAy85WhbQQ1OMxohK1
# iwTl8c6etnuyF1Wbe3zps8uxR0rMbr//ZQNEMA79NbJiNBaY5HAVCHX5z1ZbQ1Fs
# +voAA0rmb46t4Hry2CWluyMA4mUsc1zOXPShs5a9PzRb7wVKQtJE04zGfqjSRD1l
# +WPR89zh9L/Y3CAH6wf/Uf8dCnAFVV+YNGNV3CqnL8t7s2l+rkvODo4L1j42xD/r
# 45J8NQV5BcKV+m9W/90jAaLbif9ESWYE6y5eZQoclmh050tMi9mqXBIjdxxW2hoN
# 7nqRCNnRfxsZOUihODTVEQ8t1t+7Wn6WG6H9oFeQ5XSw2+pKb2VKdA8YTEbzGHgt
# 0qklu7SOzIj4D0K43upks43zUAbD5ZFUdNF/qVvujjwqA5FB9nEcg7wqXynOJ/e4
# MvMFXQy0enKcF1vVkNPte0MDv5TgWhTEIaFFrEc7q6OTEAz1oFX1IMj7VCJEuY4w
# zSm1lb+2OSetxvJ+zYYR7AkVQrd6O9w6iS8gRIVbF5bMRdyCuCQh7oHysI/sghrU
# 0U2KEk68uGxRDK2xR5hJsTnC2dX7rIXYpbh3eGtoBwTLNNzCo41JsxtGc3ATnoPz
# XlvnyPxIr6Rk66QneTGuxiXtaozi0R+C4JBEHSnNMnZqQZHvCeV5jxGcM6/oDhSu
# W4UxghnqMIIZ5gIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25p
# bmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTECEAEIrklkBVwWXiMEseJziMMwDQYJ
# YIZIAWUDBAIBBQCgfDAQBgorBgEEAYI3AgEMMQIwADAZBgkqhkiG9w0BCQMxDAYK
# KwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG
# 9w0BCQQxIgQgxXECe5iT12EXD0HzX0DpQ/nFzLXQqn7AJzuTnw9tZm0wDQYJKoZI
# hvcNAQEBBQAEggGAcG9N0HZAr5UPL6SsN6ZONm76s8aO4EVUlzKMVgz6eaGvKB8u
# +/trLVpOP4YdRR2QJx77Q8lAca1Az/qkBkDn9q7gDXnTuckgeaxZIbgjQoEKLKV7
# XxYybk/st4onEUvMqdJuyKKboUt4gOuv32LNKo1iFchUineR6fRMrEuvvi4bsnx0
# lS2j2nUbz0BRWn4fW2PCkjHoR7PykN24/fn6OoJDjkTRg588DUDwc/ZKDFoQoiMK
# AS6+fFonKDjdlDyRf8OFq7ueTvH/wxoteLbYc5SAvjRw9Qi/OIUBLxamFiv4z8eX
# pW0SJjJcw2WjY/KLDDqHC9KRgcZYn7pTPYA2RlYZSGhVogup8HkiYBabklVtI+jl
# jfQfMVmP8nNvB2bBCw1Vm9IZYtkPA1Ay0Pu/c4jyRHSsFvHFHkq3l98O8gWRXT8E
# uJ1f81rpjiCMA3O6kPVEWraG1C7mkcnFQcSbbRUbaqE7wECNrSEEbYZrxfDL+p8x
# cnG/c3ns8A5X9DJGoYIXQDCCFzwGCisGAQQBgjcDAwExghcsMIIXKAYJKoZIhvcN
# AQcCoIIXGTCCFxUCAQMxDzANBglghkgBZQMEAgEFADB4BgsqhkiG9w0BCRABBKBp
# BGcwZQIBAQYJYIZIAYb9bAcBMDEwDQYJYIZIAWUDBAIBBQAEIHHks95VcXm3f20I
# hXxqSnCtpXMWaCNA0qhE7RPDTieIAhEArtsUaGjc3J+WspL0YvCf/BgPMjAyNDAy
# MjgxODU0NTVaoIITCTCCBsIwggSqoAMCAQICEAVEr/OUnQg5pr/bP1/lYRYwDQYJ
# KoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2
# IFRpbWVTdGFtcGluZyBDQTAeFw0yMzA3MTQwMDAwMDBaFw0zNDEwMTMyMzU5NTla
# MEgxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEgMB4GA1UE
# AxMXRGlnaUNlcnQgVGltZXN0YW1wIDIwMjMwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQCjU0WHHYOOW6w+VLMj4M+f1+XS512hDgncL0ijl3o7Kpxn3GIV
# WMGpkxGnzaqyat0QKYoeYmNp01icNXG/OpfrlFCPHCDqx5o7L5Zm42nnaf5bw9Yr
# IBzBl5S0pVCB8s/LB6YwaMqDQtr8fwkklKSCGtpqutg7yl3eGRiF+0XqDWFsnf5x
# XsQGmjzwxS55DxtmUuPI1j5f2kPThPXQx/ZILV5FdZZ1/t0QoRuDwbjmUpW1R9d4
# KTlr4HhZl+NEK0rVlc7vCBfqgmRN/yPjyobutKQhZHDr1eWg2mOzLukF7qr2JPUd
# vJscsrdf3/Dudn0xmWVHVZ1KJC+sK5e+n+T9e3M+Mu5SNPvUu+vUoCw0m+PebmQZ
# BzcBkQ8ctVHNqkxmg4hoYru8QRt4GW3k2Q/gWEH72LEs4VGvtK0VBhTqYggT02ke
# fGRNnQ/fztFejKqrUBXJs8q818Q7aESjpTtC/XN97t0K/3k0EH6mXApYTAA+hWl1
# x4Nk1nXNjxJ2VqUk+tfEayG66B80mC866msBsPf7Kobse1I4qZgJoXGybHGvPrhv
# ltXhEBP+YUcKjP7wtsfVx95sJPC/QoLKoHE9nJKTBLRpcCcNT7e1NtHJXwikcKPs
# CvERLmTgyyIryvEoEyFJUX4GZtM7vvrrkTjYUQfKlLfiUKHzOtOKg8tAewIDAQAB
# o4IBizCCAYcwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MB8GA1UdIwQYMBaAFLoW2W1NhS9zKXaaL3WMaiCPnshvMB0GA1UdDgQWBBSltu8T
# 5+/N0GSh1VapZTGj3tXjSTBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0
# YW1waW5nQ0EuY3JsMIGQBggrBgEFBQcBAQSBgzCBgDAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMFgGCCsGAQUFBzAChkxodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGlt
# ZVN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCBGtbeoKm1mBe8cI1P
# ijxonNgl/8ss5M3qXSKS7IwiAqm4z4Co2efjxe0mgopxLxjdTrbebNfhYJwr7e09
# SI64a7p8Xb3CYTdoSXej65CqEtcnhfOOHpLawkA4n13IoC4leCWdKgV6hCmYtld5
# j9smViuw86e9NwzYmHZPVrlSwradOKmB521BXIxp0bkrxMZ7z5z6eOKTGnaiaXXT
# UOREEr4gDZ6pRND45Ul3CFohxbTPmJUaVLq5vMFpGbrPFvKDNzRusEEm3d5al08z
# jdSNd311RaGlWCZqA0Xe2VC1UIyvVr1MxeFGxSjTredDAHDezJieGYkD6tSRN+9N
# UvPJYCHEVkft2hFLjDLDiOZY4rbbPvlfsELWj+MXkdGqwFXjhr+sJyxB0JozSqg2
# 1Llyln6XeThIX8rC3D0y33XWNmdaifj2p8flTzU8AL2+nCpseQHc2kTmOt44Owde
# OVj0fHMxVaCAEcsUDH6uvP6k63llqmjWIso765qCNVcoFstp8jKastLYOrixRoZr
# uhf9xHdsFWyuq69zOuhJRrfVf8y2OMDY7Bz1tqG4QyzfTkx9HmhwwHcK1ALgXGC7
# KP845VJa1qwXIiNO9OzTF/tQa/8Hdx9xl0RBybhG02wyfFgvZ0dl5Rtztpn5aywG
# Ru9BHvDwX+Db2a2QgESvgBBBijCCBq4wggSWoAMCAQICEAc2N7ckVHzYR6z9KGYq
# XlswDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
# ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGln
# aUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIyMDMyMzAwMDAwMFoXDTM3MDMyMjIz
# NTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTsw
# OQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVT
# dGFtcGluZyBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMaGNQZJ
# s8E9cklRVcclA8TykTepl1Gh1tKD0Z5Mom2gsMyD+Vr2EaFEFUJfpIjzaPp985yJ
# C3+dH54PMx9QEwsmc5Zt+FeoAn39Q7SE2hHxc7Gz7iuAhIoiGN/r2j3EF3+rGSs+
# QtxnjupRPfDWVtTnKC3r07G1decfBmWNlCnT2exp39mQh0YAe9tEQYncfGpXevA3
# eZ9drMvohGS0UvJ2R/dhgxndX7RUCyFobjchu0CsX7LeSn3O9TkSZ+8OpWNs5KbF
# Hc02DVzV5huowWR0QKfAcsW6Th+xtVhNef7Xj3OTrCw54qVI1vCwMROpVymWJy71
# h6aPTnYVVSZwmCZ/oBpHIEPjQ2OAe3VuJyWQmDo4EbP29p7mO1vsgd4iFNmCKseS
# v6De4z6ic/rnH1pslPJSlRErWHRAKKtzQ87fSqEcazjFKfPKqpZzQmiftkaznTqj
# 1QPgv/CiPMpC3BhIfxQ0z9JMq++bPf4OuGQq+nUoJEHtQr8FnGZJUlD0UfM2SU2L
# INIsVzV5K6jzRWC8I41Y99xh3pP+OcD5sjClTNfpmEpYPtMDiP6zj9NeS3YSUZPJ
# jAw7W4oiqMEmCPkUEBIDfV8ju2TjY+Cm4T72wnSyPx4JduyrXUZ14mCjWAkBKAAO
# hFTuzuldyF4wEr1GnrXTdrnSDmuZDNIztM2xAgMBAAGjggFdMIIBWTASBgNVHRMB
# Af8ECDAGAQH/AgEAMB0GA1UdDgQWBBS6FtltTYUvcyl2mi91jGogj57IbzAfBgNV
# HSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYD
# VR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwH
# ATANBgkqhkiG9w0BAQsFAAOCAgEAfVmOwJO2b5ipRCIBfmbW2CFC4bAYLhBNE88w
# U86/GPvHUF3iSyn7cIoNqilp/GnBzx0H6T5gyNgL5Vxb122H+oQgJTQxZ822EpZv
# xFBMYh0MCIKoFr2pVs8Vc40BIiXOlWk/R3f7cnQU1/+rT4osequFzUNf7WC2qk+R
# Zp4snuCKrOX9jLxkJodskr2dfNBwCnzvqLx1T7pa96kQsl3p/yhUifDVinF2ZdrM
# 8HKjI/rAJ4JErpknG6skHibBt94q6/aesXmZgaNWhqsKRcnfxI2g55j7+6adcq/E
# x8HBanHZxhOACcS2n82HhyS7T6NJuXdmkfFynOlLAlKnN36TU6w7HQhJD5TNOXrd
# /yVjmScsPT9rp/Fmw0HNT7ZAmyEhQNC3EyTN3B14OuSereU0cZLXJmvkOHOrpgFP
# vT87eK1MrfvElXvtCl8zOYdBeHo46Zzh3SP9HSjTx/no8Zhf+yvYfvJGnXUsHics
# JttvFXseGYs2uJPU5vIXmVnKcPA3v5gA3yAWTyf7YGcWoWa63VXAOimGsJigK+2V
# Qbc61RWYMbRiCQ8KvYHZE/6/pNHzV9m8BPqC3jLfBInwAM1dwvnQI38AC+R2AibZ
# 8GV2QqYphwlHK+Z/GqSFD/yYlvZVVCsfgPrA8g4r5db7qS9EFUrnEw4d2zc4GqEr
# 9u3WfPwwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEB
# DAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNV
# BAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQg
# SUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJ
# BgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5k
# aWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPs
# wqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLk
# X9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDtt
# ceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hI
# qGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2
# scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm
# 2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaH
# iZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3r
# M9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJ
# B+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRES
# W+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6Kxfgom
# mfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0G
# A1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLL
# gjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKG
# N2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJv
# b3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUd
# IAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGH
# LOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7Q
# Kt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajw
# vy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQ
# Pfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFq
# I2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQxggN2MIIDcgIB
# ATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkG
# A1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3Rh
# bXBpbmcgQ0ECEAVEr/OUnQg5pr/bP1/lYRYwDQYJYIZIAWUDBAIBBQCggdEwGgYJ
# KoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNDAyMjgx
# ODU0NTVaMCsGCyqGSIb3DQEJEAIMMRwwGjAYMBYEFGbwKzLCwskPgl3OqorJxk8Z
# nM9AMC8GCSqGSIb3DQEJBDEiBCAKi3Z/dyt6uLTYmVPG2Nlp2udR5XmNwymnTrAh
# slzPAzA3BgsqhkiG9w0BCRACLzEoMCYwJDAiBCDS9uRt7XQizNHUQFdoQTZvgora
# VZquMxavTRqa1Ax4KDANBgkqhkiG9w0BAQEFAASCAgAT3mW7srL1kKvc2yRy8gyK
# m56UXKp5crD+vg3KD6zPpObgBHqK9LCRAI+5tiYprkOZ+gL+hJeVCXe+SCrQ/8mx
# O/0ynI2g/FQE343d3FY9nxiLP+wPcbdvPrw/nkgM8leff+Q18VFTAgfgEuREoh3E
# vOFmrNXXelpci5sNVl4RQ9fqJGTRE79FTfuhrOGTM/7h1DCPDZJQrJ0AVhBKoGS+
# 9aNVy57n1WegU7A0aIK2KieUthF8t57/9sCU+YHMQ2CFGTAry8wIRMiWFc7uB58K
# bqrQhfbTC6zrA7z0RRHTKdVuql8Ezg2PCvP4MO1lM/s6B6WtsAUZS8sF6s2NA9He
# +GjoKj1fE5G+BjQH5RWPIeR/gsRLpRAIbS8zHZ5QiWwEVEAT2oxIvUA+LgLLSApr
# KdIFUqT9YtheQ1rcR6FQCzZEEQDVAdnQBTrl9Zb4nINL/LrjDoWzUcZ6W0Bt3dOG
# K6uAYgWu+mCN/Sf0GXnBD+42I0KOWTJzgKC05CG5invW0RVgVhIjYCvVl9tqXsOc
# Zd2VUPeuU3rXRtGH2sCrcrwmdg23p+eM9bQwrxe3UEIToxHdl3gPJVcOi5cIqY8e
# qn7D4oOEoZTF9XTSS/ily2uk5GipJ8cLhJJMqrXzBs71wEZjNBJMJ5Nop4N3724b
# EuAnI9kNg3A01ngV9X2EQg==
# SIG # End signature block
