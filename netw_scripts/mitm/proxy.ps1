# Set proxy server information
$proxyServer = "192.168.1.1:8080"  # Replace with your proxy server and port

# Enable proxy by setting the ProxyEnable registry key
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1

# Set the ProxyServer registry key with the proxy server details
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value $proxyServer

# Optionally disable automatic proxy detection if needed
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name AutoDetect -Value 0

# Optional: Verify if the changes were applied
$proxySettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Write-Output "Proxy Settings:"
Write-Output "Proxy Enabled: $($proxySettings.ProxyEnable)"
Write-Output "Proxy Server: $($proxySettings.ProxyServer)"
# Write-Output "Proxy Override: $($proxySettings.ProxyOverride)"

# Define the path to the certificate file
$certPath = "C:\Users\hazel\Desktop\mitmproxy-ca-cert.p12"

# Load the certificate (skip prompt for validation by installing directly to the store)
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import($certPath, $certPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)

# Open the Trusted Root Certification Authorities store (for Current User)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root", "CurrentUser"

# Open the store in read-write mode
$store.Open("ReadWrite")

# Add the certificate to the store (bypassing prompt)
$store.Add($cert)

# Close the store
$store.Close()

Write-Host "Certificate imported into Trusted Root Certification Authorities store for Current User."
