#requires -Version 7.0
# Copyright (c) 2026 Tim Alderweireldt. All rights reserved.
<#!
xyOps FTP Upload Event Plugin (PowerShell 7)
Upload files to remote servers via FTP, FTPS (Explicit/Implicit), or SFTP.

Protocols:
- FTP  : Plain FTP via .NET System.Net.FtpWebRequest (port 21)
- FTPS : FTP over TLS — Explicit (STARTTLS, port 21) via .NET, Implicit (port 990) via TcpClient+SslStream
- SFTP : SSH File Transfer Protocol via Posh-SSH module (port 22)

I/O contract:
- Read one JSON object from STDIN (job), write progress/messages as JSON lines of the
  form: { "xy": 1, ... } to STDOUT.
- On success, emit: { "xy": 1, "code": 0, "data": <result>, "description": "..." }
- On error, emit:   { "xy": 1, "code": <nonzero>, "description": "..." } and exit 1.

Test locally:
  pwsh -NoProfile -ExecutionPolicy Bypass -File .\ftp.ps1 < job.json
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region xyOps Output Helpers

function Write-XY {
  param([hashtable]$Object)
  $payload = [ordered]@{ xy = 1 }
  foreach ($k in $Object.Keys) { $payload[$k] = $Object[$k] }
  [Console]::Out.WriteLine(($payload | ConvertTo-Json -Depth 20 -Compress))
  [Console]::Out.Flush()
}

function Write-XYProgress {
  param([double]$Value, [string]$Status)
  $o = @{ progress = [math]::Round($Value, 4) }
  if ($Status) { $o.status = $Status }
  Write-XY $o
}

function Write-XYSuccess {
  param($Data, [string]$Description)
  $o = @{ code = 0; data = $Data }
  if ($Description) { $o.description = $Description }
  Write-XY $o
}

function Write-XYError {
  param([int]$Code, [string]$Description)
  Write-XY @{ code = $Code; description = $Description }
}

function Read-JobFromStdin {
  $raw = [Console]::In.ReadToEnd()
  if ([string]::IsNullOrWhiteSpace($raw)) { throw 'No job JSON received on STDIN' }
  return $raw | ConvertFrom-Json -ErrorAction Stop
}

function Get-Param {
  param($Params, [string]$Name, $Default = $null)
  if ($Params.PSObject.Properties.Name -contains $Name) { return $Params.$Name }
  return $Default
}

function Get-NestedValue {
  param($Object, [string]$Path)
  if (-not $Path -or ($Path.Trim() -eq '')) { return $Object }
  $cur = $Object
  foreach ($part in $Path.Split('.')) {
    if ($null -eq $cur) { return $null }
    if ($cur -is [System.Collections.IDictionary]) {
      if (-not $cur.Contains($part)) { return $null }
      $cur = $cur[$part]
    }
    else {
      $cur = $cur.PSObject.Properties[$part].Value
    }
  }
  return $cur
}

#endregion

#region Module Installer

function Install-RequiredModules {
  param([string]$Protocol)

  if ($Protocol -ne 'sftp') { return }

  if (-not (Get-Module -ListAvailable -Name 'Posh-SSH')) {
    Write-XYProgress 0.05 'Installing Posh-SSH module (first-time SFTP setup)...'
    try {
      Install-Module -Name 'Posh-SSH' -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck
      Write-XYProgress 0.08 'Posh-SSH module installed successfully'
    }
    catch {
      throw ("Failed to install Posh-SSH module. Install manually: Install-Module -Name Posh-SSH -Scope CurrentUser -Force`n" +
             "Error: $($_.Exception.Message)")
    }
  }

  Import-Module Posh-SSH -ErrorAction Stop
}

#endregion

#region Error Handling

function Format-TransferError {
  param(
    [System.Management.Automation.ErrorRecord]$ErrorRecord,
    [string]$Phase,
    [string]$Protocol
  )

  $msg = $ErrorRecord.Exception.Message
  $innerMsg = if ($ErrorRecord.Exception.InnerException) { $ErrorRecord.Exception.InnerException.Message } else { '' }
  $fullMsg = if ($innerMsg) { "$msg — $innerMsg" } else { $msg }

  $category = 'Unknown'
  $suggestion = ''

  switch -Regex ($fullMsg) {
    # Connection errors
    'No such host|DNS|name.*resolution|could not resolve' {
      $category = 'Connection — DNS Resolution'
      $suggestion = 'Verify the hostname is correct and DNS is reachable'
      break
    }
    'actively refused|connection refused|ECONNREFUSED' {
      $category = 'Connection — Refused'
      $suggestion = "Verify the server is running and listening on the correct port for $Protocol"
      break
    }
    'timed? ?out|ETIMEDOUT' {
      $category = 'Connection — Timeout'
      $suggestion = 'Check firewall rules and network connectivity'
      break
    }
    'unreachable|EHOSTUNREACH|ENETUNREACH' {
      $category = 'Connection — Unreachable'
      $suggestion = 'Verify network connectivity and routing to the server'
      break
    }
    # Authentication errors
    '530|not log|login.*fail|auth.*fail|invalid.*credential|access denied.*login|permission denied.*publickey' {
      $category = 'Authentication — Failed'
      $suggestion = 'Verify username/password or SSH key. Check if the account is active and not locked.'
      break
    }
    'key.*invalid|key.*not.*found|private.*key|bad.*key|key.*format' {
      $category = 'Authentication — SSH Key Error'
      $suggestion = 'Verify the SSH key file exists, is readable, and in the correct format (RSA/ED25519/ECDSA/DSA)'
      break
    }
    'passphrase|decrypt.*key' {
      $category = 'Authentication — Key Passphrase'
      $suggestion = 'The SSH key is encrypted. Provide the correct passphrase via parameter or FTP_SSH_KEY_PASSPHRASE secret.'
      break
    }
    # Permission errors
    '550.*permission|553|access.*denied|permission.*denied|not.*authorized' {
      $category = 'Permission — Access Denied'
      $suggestion = 'The user does not have write permission on the remote path. Check directory permissions on the server.'
      break
    }
    '550.*no such|550.*not found|no such file|directory.*not.*exist' {
      $category = 'Permission — Path Not Found'
      $suggestion = 'The remote path does not exist. Enable "Create Remote Directories" or verify the path is correct.'
      break
    }
    # Transfer errors
    '552|disk.*full|no space|quota.*exceeded' {
      $category = 'Transfer — Disk Full'
      $suggestion = 'The remote server has insufficient disk space or the user quota is exceeded'
      break
    }
    '451|transfer.*abort|upload.*fail|write.*fail' {
      $category = 'Transfer — Failed'
      $suggestion = 'The file transfer was interrupted. Check server logs and retry.'
      break
    }
    # Protocol/TLS errors
    'SSL|TLS|certificate|handshake|secure.*channel' {
      $category = 'Protocol — TLS/SSL Error'
      $suggestion = "Check TLS configuration. For FTPS, verify the server supports the selected mode (Explicit/Implicit)."
      break
    }
    'STARTTLS|AUTH TLS' {
      $category = 'Protocol — STARTTLS Failed'
      $suggestion = 'The server does not support FTPS Explicit (STARTTLS). Try Implicit mode or plain FTP.'
      break
    }
  }

  if ($category -eq 'Unknown') {
    $category = "$Phase — Error"
    $suggestion = 'Check the error details and server configuration'
  }

  Write-XY @{ table = @{
    title = 'Error Details'
    header = @('Property', 'Value')
    rows = @(
      @('Category', $category),
      @('Phase', $Phase),
      @('Protocol', $Protocol.ToUpper()),
      @('Details', $fullMsg),
      @('Suggestion', $suggestion)
    )
    caption = ''
  } }

  return "${category}: $fullMsg"
}

#endregion

#region FTP/FTPS Explicit Operations (.NET FtpWebRequest)

function New-FTPRequest {
  param(
    [string]$Url,
    [string]$Method,
    [System.Net.NetworkCredential]$Credential,
    [bool]$EnableSsl,
    [bool]$PassiveMode
  )

  # Accept all server certificates for FTPS (common for internal/self-signed certs)
  if ($EnableSsl) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { param($s, $c, $ch, $e) $true }
  }

  $request = [System.Net.FtpWebRequest]::Create($Url)
  $request.Method = $Method
  $request.Credentials = $Credential
  $request.EnableSsl = $EnableSsl
  $request.UsePassive = $PassiveMode
  $request.UseBinary = $true
  $request.KeepAlive = $false

  return $request
}

function Get-FTPBaseUrl {
  param([string]$HostName, [int]$Port)
  return "ftp://${HostName}:${Port}"
}

function Test-FTPFileExists {
  param(
    [string]$BaseUrl,
    [string]$RemoteFile,
    [System.Net.NetworkCredential]$Credential,
    [bool]$EnableSsl,
    [bool]$PassiveMode
  )

  try {
    $url = "$BaseUrl/$($RemoteFile.TrimStart('/'))"
    $request = New-FTPRequest -Url $url -Method ([System.Net.WebRequestMethods+Ftp]::GetFileSize) `
                              -Credential $Credential -EnableSsl $EnableSsl -PassiveMode $PassiveMode
    $response = $request.GetResponse()
    $size = $response.ContentLength
    $response.Close()
    return @{ Exists = $true; Size = $size }
  }
  catch {
    return @{ Exists = $false; Size = 0 }
  }
}

function New-FTPRemoteDirectory {
  param(
    [string]$BaseUrl,
    [string]$DirPath,
    [System.Net.NetworkCredential]$Credential,
    [bool]$EnableSsl,
    [bool]$PassiveMode
  )

  $parts = $DirPath.Split('/') | Where-Object { $_ }
  $currentPath = ''

  foreach ($part in $parts) {
    $currentPath += "/$part"
    try {
      $url = "$BaseUrl$currentPath/"
      $request = New-FTPRequest -Url $url -Method ([System.Net.WebRequestMethods+Ftp]::MakeDirectory) `
                                -Credential $Credential -EnableSsl $EnableSsl -PassiveMode $PassiveMode
      $response = $request.GetResponse()
      $response.Close()
    }
    catch {
      # Directory likely already exists — ignore 550 errors
      if ($_.Exception.InnerException -and $_.Exception.InnerException.Message -notmatch '550') {
        if ($_.Exception.Message -notmatch '550') { throw }
      }
    }
  }
}

function Send-FTPSingleFile {
  param(
    [string]$BaseUrl,
    [string]$RemoteFile,
    [string]$LocalFilePath,
    [System.Net.NetworkCredential]$Credential,
    [bool]$EnableSsl,
    [bool]$PassiveMode
  )

  $url = "$BaseUrl/$($RemoteFile.TrimStart('/'))"
  $request = New-FTPRequest -Url $url -Method ([System.Net.WebRequestMethods+Ftp]::UploadFile) `
                            -Credential $Credential -EnableSsl $EnableSsl -PassiveMode $PassiveMode

  $fileBytes = [System.IO.File]::ReadAllBytes($LocalFilePath)
  $stream = $request.GetRequestStream()
  try {
    $stream.Write($fileBytes, 0, $fileBytes.Length)
  }
  finally {
    $stream.Close()
  }

  $response = $request.GetResponse()
  $response.Close()

  return $fileBytes.Length
}

#endregion

#region FTPS Implicit Operations (TcpClient + SslStream)

function Read-FTPSResponse {
  param([System.IO.StreamReader]$Reader)

  $line = $Reader.ReadLine()
  if ($null -eq $line) { throw 'Connection closed by remote server' }

  # Handle multi-line responses (e.g., "220-Welcome\r\n220 Ready")
  while ($line -match '^\d{3}-') {
    $nextLine = $Reader.ReadLine()
    if ($null -eq $nextLine) { break }
    $line = $nextLine
  }

  $code = 0
  $message = $line
  if ($line -match '^(\d{3})\s?(.*)') {
    $code = [int]$Matches[1]
    $message = $Matches[2]
  }

  return @{ Code = $code; Text = $line; Message = $message }
}

function New-ImplicitFTPSSession {
  param([string]$HostName, [int]$Port, [string]$Username, [string]$Password)

  $tcpClient = [System.Net.Sockets.TcpClient]::new()
  $tcpClient.Connect($HostName, $Port)

  $sslCallback = [System.Net.Security.RemoteCertificateValidationCallback]{
    param($sender, $certificate, $chain, $sslPolicyErrors)
    return $true
  }

  $sslStream = [System.Net.Security.SslStream]::new(
    $tcpClient.GetStream(), $false, $sslCallback
  )
  $sslStream.AuthenticateAsClient($HostName)

  $reader = [System.IO.StreamReader]::new($sslStream, [System.Text.Encoding]::UTF8)
  $writer = [System.IO.StreamWriter]::new($sslStream, [System.Text.Encoding]::UTF8)
  $writer.AutoFlush = $true

  # Read welcome banner
  $resp = Read-FTPSResponse -Reader $reader
  if ($resp.Code -ge 400) { throw "Server rejected connection: $($resp.Text)" }

  # Login
  $writer.WriteLine("USER $Username")
  $resp = Read-FTPSResponse -Reader $reader
  if ($resp.Code -ge 400 -and $resp.Code -ne 331) { throw "USER command failed: $($resp.Text)" }

  $writer.WriteLine("PASS $Password")
  $resp = Read-FTPSResponse -Reader $reader
  if ($resp.Code -ge 400) { throw "Authentication failed: $($resp.Text)" }

  # Binary mode
  $writer.WriteLine("TYPE I")
  $null = Read-FTPSResponse -Reader $reader

  # Set protection buffer size and data channel protection level for FTPS
  $writer.WriteLine("PBSZ 0")
  $null = Read-FTPSResponse -Reader $reader

  $writer.WriteLine("PROT P")
  $null = Read-FTPSResponse -Reader $reader

  return @{
    Client    = $tcpClient
    SslStream = $sslStream
    Reader    = $reader
    Writer    = $writer
    HostName  = $HostName
  }
}

function Close-ImplicitFTPSSession {
  param([hashtable]$Session)

  try { $Session.Writer.WriteLine("QUIT"); $null = Read-FTPSResponse -Reader $Session.Reader } catch {}
  try { $Session.Reader.Dispose() } catch {}
  try { $Session.Writer.Dispose() } catch {}
  try { $Session.SslStream.Dispose() } catch {}
  try { $Session.Client.Dispose() } catch {}
}

function Open-ImplicitFTPSDataChannel {
  param([hashtable]$Session)

  $Session.Writer.WriteLine("PASV")
  $resp = Read-FTPSResponse -Reader $Session.Reader

  if ($resp.Text -match '\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)') {
    $dataPort = [int]$Matches[5] * 256 + [int]$Matches[6]
  }
  else {
    throw "Failed to parse PASV response: $($resp.Text)"
  }

  $dataClient = [System.Net.Sockets.TcpClient]::new()
  $dataClient.Connect($Session.HostName, $dataPort)

  $sslCallback = [System.Net.Security.RemoteCertificateValidationCallback]{
    param($sender, $certificate, $chain, $sslPolicyErrors)
    return $true
  }

  $dataSsl = [System.Net.Security.SslStream]::new(
    $dataClient.GetStream(), $false, $sslCallback
  )
  $dataSsl.AuthenticateAsClient($Session.HostName)

  return @{ Client = $dataClient; SslStream = $dataSsl }
}

function New-ImplicitFTPSDirectory {
  param([hashtable]$Session, [string]$DirPath)

  $parts = $DirPath.Split('/') | Where-Object { $_ }
  $currentPath = ''

  foreach ($part in $parts) {
    $currentPath += "/$part"
    $Session.Writer.WriteLine("MKD $currentPath")
    $null = Read-FTPSResponse -Reader $Session.Reader   # Ignore errors if dir already exists
  }
}

function Test-ImplicitFTPSFileExists {
  param([hashtable]$Session, [string]$RemoteFile)

  $Session.Writer.WriteLine("SIZE $RemoteFile")
  $resp = Read-FTPSResponse -Reader $Session.Reader

  if ($resp.Code -eq 213) {
    $size = 0
    if ($resp.Message -match '(\d+)') { $size = [long]$Matches[1] }
    return @{ Exists = $true; Size = $size }
  }
  return @{ Exists = $false; Size = 0 }
}

function Send-ImplicitFTPSSingleFile {
  param([hashtable]$Session, [string]$RemoteFile, [string]$LocalFilePath)

  $dataChannel = Open-ImplicitFTPSDataChannel -Session $Session

  $fileBytes = [System.IO.File]::ReadAllBytes($LocalFilePath)

  try {
    $Session.Writer.WriteLine("STOR $RemoteFile")
    $resp = Read-FTPSResponse -Reader $Session.Reader
    if ($resp.Code -ge 400) { throw "STOR command failed: $($resp.Text)" }

    $dataChannel.SslStream.Write($fileBytes, 0, $fileBytes.Length)
    $dataChannel.SslStream.Flush()
  }
  finally {
    try { $dataChannel.SslStream.Close() } catch {}
    try { $dataChannel.Client.Close() } catch {}
  }

  # Read transfer complete response
  $resp = Read-FTPSResponse -Reader $Session.Reader

  return $fileBytes.Length
}

#endregion

#region SFTP Operations (Posh-SSH)

function New-SFTPConnection {
  param(
    [string]$HostName,
    [int]$Port,
    [string]$Username,
    [string]$Password,
    [string]$KeyPath,
    [string]$KeyPassphrase
  )

  # Build credential — for key auth, the credential password is used as the key passphrase
  $securePass = if ($KeyPath -and $KeyPassphrase) {
    ConvertTo-SecureString $KeyPassphrase -AsPlainText -Force
  }
  elseif ($Password) {
    ConvertTo-SecureString $Password -AsPlainText -Force
  }
  else {
    [System.Security.SecureString]::new()
  }

  $credential = [System.Management.Automation.PSCredential]::new($Username, $securePass)

  $sessionParams = @{
    ComputerName = $HostName
    Port         = $Port
    Credential   = $credential
    AcceptKey    = $true
    Force        = $true
    ErrorAction  = 'Stop'
  }

  if ($KeyPath) {
    if (-not (Test-Path $KeyPath)) {
      throw "SSH key file not found: $KeyPath"
    }
    $sessionParams['KeyFile'] = $KeyPath
  }

  $session = New-SFTPSession @sessionParams
  return $session
}

function Test-SFTPFileExists {
  param([int]$SessionId, [string]$RemotePath)

  try {
    $item = Get-SFTPItem -SessionId $SessionId -Path $RemotePath -ErrorAction Stop
    return @{ Exists = $true; Size = $item.Length }
  }
  catch {
    return @{ Exists = $false; Size = 0 }
  }
}

function New-SFTPRemoteDirectory {
  param([int]$SessionId, [string]$DirPath)

  $parts = $DirPath.Split('/') | Where-Object { $_ }
  $currentPath = ''

  foreach ($part in $parts) {
    $currentPath += "/$part"
    if (-not (Test-SFTPPath -SessionId $SessionId -Path $currentPath)) {
      New-SFTPItem -SessionId $SessionId -Path $currentPath -ItemType Directory -ErrorAction Stop | Out-Null
    }
  }
}

function Send-SFTPSingleFile {
  param(
    [int]$SessionId,
    [string]$LocalFilePath,
    [string]$RemoteDir,
    [bool]$Overwrite
  )

  $destDir = $RemoteDir.TrimEnd('/') + '/'

  $params = @{
    SessionId   = $SessionId
    Path        = $LocalFilePath
    Destination = $destDir
    ErrorAction = 'Stop'
  }
  if ($Overwrite) { $params['Force'] = $true }

  Set-SFTPItem @params

  return (Get-Item $LocalFilePath).Length
}

function Close-SFTPConnection {
  param([int]$SessionId)

  try { Remove-SFTPSession -SessionId $SessionId -ErrorAction SilentlyContinue | Out-Null } catch {}
}

#endregion

#region File Resolution

function Resolve-UploadFiles {
  param($Params, $JobInput, [string]$Cwd)

  $fileSource = (Get-Param $Params 'fileSource' 'local').ToLower()
  $files = [System.Collections.ArrayList]::new()

  switch ($fileSource) {
    'local' {
      $localPath = Get-Param $Params 'localPath' ''
      if (-not $localPath) { throw 'Local Path is required when File Source is "Local file or folder"' }

      if ($localPath -match '[\*\?]') {
        # Glob pattern
        $resolved = @(Get-ChildItem -Path $localPath -File -ErrorAction SilentlyContinue)
        if ($resolved.Count -eq 0) {
          throw "No files found matching pattern: $localPath"
        }
        foreach ($item in $resolved) {
          $null = $files.Add(@{
            LocalPath  = $item.FullName
            RemoteName = $item.Name
            TempFile   = $false
            Size       = $item.Length
          })
        }
      }
      elseif (Test-Path $localPath -PathType Container) {
        # Directory — upload all files recursively
        $items = @(Get-ChildItem -Path $localPath -Recurse -File)
        if ($items.Count -eq 0) { throw "No files found in directory: $localPath" }
        $basePath = (Resolve-Path $localPath).Path
        foreach ($item in $items) {
          $relativePath = $item.FullName.Substring($basePath.Length).TrimStart([IO.Path]::DirectorySeparatorChar).Replace('\', '/')
          $null = $files.Add(@{
            LocalPath  = $item.FullName
            RemoteName = $relativePath
            TempFile   = $false
            Size       = $item.Length
          })
        }
      }
      elseif (Test-Path $localPath -PathType Leaf) {
        # Single file
        $item = Get-Item $localPath
        $null = $files.Add(@{
          LocalPath  = $item.FullName
          RemoteName = $item.Name
          TempFile   = $false
          Size       = $item.Length
        })
      }
      else {
        throw "File or folder not found: $localPath"
      }
    }

    'content' {
      $content  = Get-Param $Params 'content' ''
      $fileName = Get-Param $Params 'contentFileName' 'upload.txt'
      if (-not $content) { throw 'Content is required when File Source is "Raw text content"' }
      if (-not $fileName) { $fileName = 'upload.txt' }

      $tempFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), $fileName)
      [System.IO.File]::WriteAllText($tempFile, $content, [System.Text.Encoding]::UTF8)

      $null = $files.Add(@{
        LocalPath  = $tempFile
        RemoteName = $fileName
        TempFile   = $true
        Size       = (Get-Item $tempFile).Length
      })
    }

    'jobdata' {
      $dataPath = Get-Param $Params 'dataPath' ''
      $fileName = Get-Param $Params 'dataFileName' 'upload.txt'
      if (-not $JobInput) { throw 'No input data available from previous job' }

      $inputData = if ($JobInput.PSObject.Properties.Name -contains 'data') { $JobInput.data } else { $JobInput }
      $value = Get-NestedValue $inputData $dataPath

      if ($null -eq $value) { throw "No data found at path '$dataPath' in previous job output" }

      $content = if ($value -is [string]) { $value } else { $value | ConvertTo-Json -Depth 20 }
      if (-not $fileName) { $fileName = 'upload.txt' }

      $tempFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), $fileName)
      [System.IO.File]::WriteAllText($tempFile, $content, [System.Text.Encoding]::UTF8)

      $null = $files.Add(@{
        LocalPath  = $tempFile
        RemoteName = $fileName
        TempFile   = $true
        Size       = (Get-Item $tempFile).Length
      })
    }

    'jobfiles' {
      if (-not $JobInput) { throw 'No input available from previous job' }

      $inputFiles = if ($JobInput.PSObject.Properties.Name -contains 'files') { $JobInput.files } else { $null }
      if (-not $inputFiles -or $inputFiles.Count -eq 0) {
        throw 'No files found in previous job output. The previous event plugin must emit files via Write-XY @{ files = $files }.'
      }

      # xyOps pre-downloads files from the previous workflow step into CWD
      $baseDir = if ($Cwd -and (Test-Path $Cwd -PathType Container)) {
        $Cwd
      } else {
        (Get-Location).Path
      }

      foreach ($inputFile in $inputFiles) {
        $fileName = if ($inputFile -is [string]) { $inputFile } else { $inputFile.filename }
        if (-not $fileName) { continue }

        $localPath = [System.IO.Path]::Combine($baseDir, $fileName)

        if (-not (Test-Path $localPath -PathType Leaf)) {
          throw "Previous job file not found: $fileName. File not found at: $localPath"
        }

        $item = Get-Item $localPath
        $null = $files.Add(@{
          LocalPath  = $item.FullName
          RemoteName = $item.Name
          TempFile   = $false
          Size       = $item.Length
        })
      }
    }

    default {
      throw "Unknown file source: $fileSource. Expected: local, content, jobdata, or jobfiles."
    }
  }

  return $files.ToArray()
}

#endregion

#region Main Orchestrator

function Invoke-FTPUpload {
  param($Params, $JobInput, [string]$Cwd)

  Write-XYProgress 0.02 'Starting FTP Upload...'

  # ── Resolve parameters with secret vault fallback ──────────────────────
  $protocol = (Get-Param $Params 'protocol' 'ftp').ToLower()

  $ftpHost = (Get-Param $Params 'host' '').Trim()
  if (-not $ftpHost) { $ftpHost = if ($env:FTP_HOST) { $env:FTP_HOST.Trim() } else { '' } }

  $portStr = (Get-Param $Params 'port' '').ToString().Trim()
  if (-not $portStr) { $portStr = if ($env:FTP_PORT) { $env:FTP_PORT.Trim() } else { '' } }

  $username = (Get-Param $Params 'username' '').Trim()
  if (-not $username) { $username = if ($env:FTP_USERNAME) { $env:FTP_USERNAME.Trim() } else { '' } }

  $password = (Get-Param $Params 'password' '').Trim()
  if (-not $password) { $password = if ($env:FTP_PASSWORD) { $env:FTP_PASSWORD.Trim() } else { '' } }

  $ftpsMode = (Get-Param $Params 'ftpsMode' 'explicit').ToLower()

  $sshKeyPath = (Get-Param $Params 'sshKeyPath' '').Trim()
  if (-not $sshKeyPath) { $sshKeyPath = if ($env:FTP_SSH_KEY_PATH) { $env:FTP_SSH_KEY_PATH.Trim() } else { '' } }

  $sshKeyPassphrase = (Get-Param $Params 'sshKeyPassphrase' '').Trim()
  if (-not $sshKeyPassphrase) { $sshKeyPassphrase = if ($env:FTP_SSH_KEY_PASSPHRASE) { $env:FTP_SSH_KEY_PASSPHRASE.Trim() } else { '' } }

  $remotePath   = (Get-Param $Params 'remotePath' '').Trim().TrimEnd('/')
  $createDirs   = if ($Params.PSObject.Properties.Name -contains 'createRemoteDirs') { [bool]$Params.createRemoteDirs } else { $true }
  $ifFileExists = (Get-Param $Params 'ifFileExists' 'overwrite').ToLower()
  $passiveMode  = if ($Params.PSObject.Properties.Name -contains 'passiveMode') { [bool]$Params.passiveMode } else { $true }

  # ── Auto-detect port ───────────────────────────────────────────────────
  $port = 0
  if ($portStr -and $portStr -match '^\d+$') {
    $port = [int]$portStr
  }
  else {
    $port = switch ($protocol) {
      'ftp'  { 21 }
      'ftps' { if ($ftpsMode -eq 'implicit') { 990 } else { 21 } }
      'sftp' { 22 }
      default { 21 }
    }
  }

  # ── Validation ─────────────────────────────────────────────────────────
  Write-XYProgress 0.04 'Validating parameters...'

  if (-not $ftpHost)    { throw 'Host is required. Provide it as a parameter or configure the FTP_HOST secret in the vault.' }
  if (-not $username)   { throw 'Username is required. Provide it as a parameter or configure the FTP_USERNAME secret in the vault.' }
  if (-not $remotePath) { throw 'Remote Path is required.' }

  if ($protocol -eq 'sftp' -and -not $password -and -not $sshKeyPath) {
    throw 'SFTP requires either a password or an SSH key. Provide a password or configure FTP_SSH_KEY_PATH.'
  }
  if ($protocol -ne 'sftp' -and -not $password) {
    throw 'Password is required for FTP/FTPS. Provide it as a parameter or configure the FTP_PASSWORD secret in the vault.'
  }

  # ── Display configuration ──────────────────────────────────────────────
  $authMethod = switch ($protocol) {
    'sftp' { if ($sshKeyPath) { "SSH Key ($sshKeyPath)" } else { 'Password' } }
    default { 'Password' }
  }
  $protocolDesc = switch ($protocol) {
    'ftp'  { 'FTP (Plain)' }
    'ftps' { "FTPS ($( ($ftpsMode.Substring(0,1).ToUpper() + $ftpsMode.Substring(1)) ) TLS)" }
    'sftp' { 'SFTP (SSH)' }
  }

  Write-XY @{ table = @{
    title  = 'Configuration'
    header = @('Setting', 'Value')
    rows   = @(
      @('Protocol', $protocolDesc),
      @('Host', $ftpHost),
      @('Port', $port),
      @('Username', $username),
      @('Auth Method', $authMethod),
      @('Remote Path', $remotePath),
      @('Create Remote Dirs', $(if ($createDirs) { 'Yes' } else { 'No' })),
      @('If File Exists', ($ifFileExists.Substring(0,1).ToUpper() + $ifFileExists.Substring(1))),
      @('Passive Mode', $(if ($passiveMode) { 'Yes' } else { 'N/A (SFTP)' }))
    )
    caption = ''
  } }

  # ── Install required modules ───────────────────────────────────────────
  Install-RequiredModules -Protocol $protocol

  # ── Resolve files to upload ────────────────────────────────────────────
  Write-XYProgress 0.10 'Resolving files to upload...'
  $filesToUpload = @(Resolve-UploadFiles -Params $Params -JobInput $JobInput -Cwd $Cwd)

  Write-XY @{ table = @{
    title  = 'Files to Upload'
    header = @('#', 'File', 'Size')
    rows   = @(
      $filesToUpload | ForEach-Object -Begin { $i = 0 } -Process {
        $i++
        ,@($i, $_.RemoteName, "$( '{0:N0}' -f $_.Size ) bytes")
      }
    )
    caption = "$($filesToUpload.Count) file(s) ready for upload"
  } }

  # ── Connect and upload ─────────────────────────────────────────────────
  $results       = [System.Collections.ArrayList]::new()
  $totalSize     = [long]0
  $skippedCount  = 0
  $uploadedCount = 0
  $ftpSession    = $null
  $sftpSession   = $null

  try {
    Write-XYProgress 0.15 "Connecting to ${ftpHost}:${port} via $($protocol.ToUpper())..."

    # ── SFTP path ──────────────────────────────────────────────────────
    if ($protocol -eq 'sftp') {

      $sftpSession = New-SFTPConnection -HostName $ftpHost -Port $port -Username $username `
                                        -Password $password -KeyPath $sshKeyPath -KeyPassphrase $sshKeyPassphrase
      $sessionId = $sftpSession.SessionId

      Write-XYProgress 0.20 'Connected via SFTP'

      if ($createDirs) {
        Write-XYProgress 0.22 "Creating remote directory: $remotePath"
        New-SFTPRemoteDirectory -SessionId $sessionId -DirPath $remotePath
      }

      $fileIndex = 0
      foreach ($file in $filesToUpload) {
        $fileIndex++
        $progress = 0.25 + (0.65 * ($fileIndex / $filesToUpload.Count))
        $remoteFile = "$remotePath/$($file.RemoteName)"
        $remoteDir  = $remotePath

        # Handle subdirectories in remote name (e.g., folder uploads)
        if ($file.RemoteName -match '/') {
          $remoteDir = "$remotePath/$( [System.IO.Path]::GetDirectoryName($file.RemoteName).Replace('\', '/') )"
          if ($createDirs) { New-SFTPRemoteDirectory -SessionId $sessionId -DirPath $remoteDir }
        }

        Write-XYProgress $progress "Uploading ($fileIndex/$($filesToUpload.Count)): $($file.RemoteName)"

        # Check file existence
        if ($ifFileExists -ne 'overwrite') {
          $existsCheck = Test-SFTPFileExists -SessionId $sessionId -RemotePath $remoteFile
          if ($existsCheck.Exists) {
            if ($ifFileExists -eq 'skip') {
              $skippedCount++
              $null = $results.Add(@{ name = $file.RemoteName; remotePath = $remoteFile; size = $file.Size; status = 'skipped' })
              continue
            }
            elseif ($ifFileExists -eq 'error') {
              throw "File already exists on remote server: $remoteFile"
            }
          }
        }

        $uploadSize = Send-SFTPSingleFile -SessionId $sessionId -LocalFilePath $file.LocalPath `
                                          -RemoteDir $remoteDir -Overwrite ($ifFileExists -eq 'overwrite')
        $totalSize += $uploadSize
        $uploadedCount++
        $null = $results.Add(@{ name = $file.RemoteName; remotePath = $remoteFile; size = $uploadSize; status = 'uploaded' })
      }
    }

    # ── FTPS Implicit path ─────────────────────────────────────────────
    elseif ($protocol -eq 'ftps' -and $ftpsMode -eq 'implicit') {

      $ftpSession = New-ImplicitFTPSSession -HostName $ftpHost -Port $port -Username $username -Password $password

      Write-XYProgress 0.20 'Connected via FTPS (Implicit TLS)'

      if ($createDirs) {
        Write-XYProgress 0.22 "Creating remote directory: $remotePath"
        New-ImplicitFTPSDirectory -Session $ftpSession -DirPath $remotePath
      }

      $fileIndex = 0
      foreach ($file in $filesToUpload) {
        $fileIndex++
        $progress = 0.25 + (0.65 * ($fileIndex / $filesToUpload.Count))
        $remoteFile = "$remotePath/$($file.RemoteName)"

        # Handle subdirectories in remote name
        if ($file.RemoteName -match '/') {
          $subDir = "$remotePath/$( [System.IO.Path]::GetDirectoryName($file.RemoteName).Replace('\', '/') )"
          if ($createDirs) { New-ImplicitFTPSDirectory -Session $ftpSession -DirPath $subDir }
        }

        Write-XYProgress $progress "Uploading ($fileIndex/$($filesToUpload.Count)): $($file.RemoteName)"

        # Check file existence
        if ($ifFileExists -ne 'overwrite') {
          $existsCheck = Test-ImplicitFTPSFileExists -Session $ftpSession -RemoteFile $remoteFile
          if ($existsCheck.Exists) {
            if ($ifFileExists -eq 'skip') {
              $skippedCount++
              $null = $results.Add(@{ name = $file.RemoteName; remotePath = $remoteFile; size = $file.Size; status = 'skipped' })
              continue
            }
            elseif ($ifFileExists -eq 'error') {
              throw "File already exists on remote server: $remoteFile"
            }
          }
        }

        $uploadSize = Send-ImplicitFTPSSingleFile -Session $ftpSession -RemoteFile $remoteFile -LocalFilePath $file.LocalPath
        $totalSize += $uploadSize
        $uploadedCount++
        $null = $results.Add(@{ name = $file.RemoteName; remotePath = $remoteFile; size = $uploadSize; status = 'uploaded' })
      }
    }

    # ── FTP / FTPS Explicit path ───────────────────────────────────────
    else {

      $enableSsl  = ($protocol -eq 'ftps')
      $credential = [System.Net.NetworkCredential]::new($username, $password)
      $baseUrl    = Get-FTPBaseUrl -HostName $ftpHost -Port $port

      Write-XYProgress 0.20 "Connected via $($protocol.ToUpper())$(if ($enableSsl) { ' (Explicit TLS)' } else { '' })"

      if ($createDirs) {
        Write-XYProgress 0.22 "Creating remote directory: $remotePath"
        New-FTPRemoteDirectory -BaseUrl $baseUrl -DirPath $remotePath -Credential $credential `
                               -EnableSsl $enableSsl -PassiveMode $passiveMode
      }

      $fileIndex = 0
      foreach ($file in $filesToUpload) {
        $fileIndex++
        $progress = 0.25 + (0.65 * ($fileIndex / $filesToUpload.Count))
        $remoteFile = "$remotePath/$($file.RemoteName)"

        # Handle subdirectories in remote name
        if ($file.RemoteName -match '/') {
          $subDir = "$remotePath/$( [System.IO.Path]::GetDirectoryName($file.RemoteName).Replace('\', '/') )"
          if ($createDirs) {
            New-FTPRemoteDirectory -BaseUrl $baseUrl -DirPath $subDir -Credential $credential `
                                   -EnableSsl $enableSsl -PassiveMode $passiveMode
          }
        }

        Write-XYProgress $progress "Uploading ($fileIndex/$($filesToUpload.Count)): $($file.RemoteName)"

        # Check file existence
        if ($ifFileExists -ne 'overwrite') {
          $existsCheck = Test-FTPFileExists -BaseUrl $baseUrl -RemoteFile $remoteFile -Credential $credential `
                                            -EnableSsl $enableSsl -PassiveMode $passiveMode
          if ($existsCheck.Exists) {
            if ($ifFileExists -eq 'skip') {
              $skippedCount++
              $null = $results.Add(@{ name = $file.RemoteName; remotePath = $remoteFile; size = $file.Size; status = 'skipped' })
              continue
            }
            elseif ($ifFileExists -eq 'error') {
              throw "File already exists on remote server: $remoteFile"
            }
          }
        }

        $uploadSize = Send-FTPSingleFile -BaseUrl $baseUrl -RemoteFile $remoteFile -LocalFilePath $file.LocalPath `
                                         -Credential $credential -EnableSsl $enableSsl -PassiveMode $passiveMode
        $totalSize += $uploadSize
        $uploadedCount++
        $null = $results.Add(@{ name = $file.RemoteName; remotePath = $remoteFile; size = $uploadSize; status = 'uploaded' })
      }
    }

    # ── Display results ──────────────────────────────────────────────────
    Write-XYProgress 0.95 'Upload complete'

    $resultRows = @($results | ForEach-Object -Begin { $i = 0 } -Process {
      $i++
      $statusIcon = switch ($_.status) { 'uploaded' { 'Uploaded' }; 'skipped' { 'Skipped' }; default { $_.status } }
      ,@($i, $_.name, "$( '{0:N0}' -f $_.size ) bytes", $statusIcon)
    })

    Write-XY @{ table = @{
      title   = 'Upload Results'
      header  = @('#', 'File', 'Size', 'Status')
      rows    = $resultRows
      caption = "$uploadedCount uploaded, $skippedCount skipped, $( '{0:N0}' -f $totalSize ) bytes total"
    } }

    # ── Build output data ────────────────────────────────────────────────
    return [pscustomobject]@{
      tool         = 'ftpUpload'
      success      = $true
      protocol     = $protocol
      host         = $ftpHost
      port         = $port
      remotePath   = $remotePath
      files        = @($results)
      totalFiles   = $uploadedCount
      totalSize    = $totalSize
      skippedFiles = $skippedCount
      timestamp    = [datetime]::UtcNow.ToString('o')
    }
  }
  catch {
    # Categorised error handling
    $phase = switch -Regex ($_.Exception.Message) {
      'resolv|DNS|refused|timeout|unreachable|connect' { 'Connection'; break }
      'auth|login|credential|key.*invalid|passphrase'  { 'Authentication'; break }
      'permission|denied|550|553'                      { 'Permission'; break }
      'SSL|TLS|certificate|handshake'                  { 'Protocol'; break }
      default                                          { 'Transfer' }
    }

    $errorMsg = Format-TransferError -ErrorRecord $_ -Phase $phase -Protocol $protocol
    throw $errorMsg
  }
  finally {
    # Cleanup connections
    if ($ftpSession)  { Close-ImplicitFTPSSession -Session $ftpSession }
    if ($sftpSession) { Close-SFTPConnection -SessionId $sftpSession.SessionId }

    # Cleanup temp files
    foreach ($file in $filesToUpload) {
      if ($file.TempFile -and (Test-Path $file.LocalPath)) {
        Remove-Item $file.LocalPath -Force -ErrorAction SilentlyContinue
      }
    }
  }
}

#endregion

#region Main Entry Point

try {
  $job    = Read-JobFromStdin
  $Params = $job.params

  # Event plugin STDIN: cwd and input are top-level properties
  $Cwd = if ($job.PSObject.Properties.Name -contains 'cwd') { $job.cwd } else { $null }

  # Resolve job input from the previous workflow step
  $JobInput = $null
  if ($job.PSObject.Properties.Name -contains 'input') {
    $JobInput = $job.input
  }
  # Fallback: top-level "data" / "files" (for local testing)
  if (-not $JobInput) {
    $hasData  = $job.PSObject.Properties.Name -contains 'data'
    $hasFiles = $job.PSObject.Properties.Name -contains 'files'
    if ($hasData -or $hasFiles) {
      $JobInput = [PSCustomObject]@{
        data  = if ($hasData)  { $job.data }  else { $null }
        files = if ($hasFiles) { $job.files } else { @() }
      }
    }
  }

  if ($Cwd -and (Test-Path $Cwd -PathType Container)) { Set-Location $Cwd }

  $result = Invoke-FTPUpload -Params $Params -JobInput $JobInput -Cwd $Cwd
  Write-XYSuccess -Data $result -Description "Uploaded $($result.totalFiles) file(s) via $($result.protocol.ToUpper()) to $($result.host)"
  exit 0
}
catch {
  Write-XYError -Code 1 -Description $_.Exception.Message
  exit 1
}

#endregion
