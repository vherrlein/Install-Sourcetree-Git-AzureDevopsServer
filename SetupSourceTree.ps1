#settings
$devOpsCollectionUrl="https://<Your_AzureDevOps_FQDN>/tfs/<Your_Project_Collection_Name>"

$defaultPatName="SourceTree"

########  DO NOT MODIFY BELOW  ########

## HELPERS
function Disable-CertificateChecks{
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
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
 }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    [ServerCertificateValidationCallback]::Ignore()
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]([string]::Join(",",$([enum]::GetNames([System.Net.SecurityProtocolType]) | ?{$_ -ne "SystemDefault"})))
}
function Get-Software ($filter)  {
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | %{
        gp $_ -ErrorAction 0|?{$filter -eq $null -or $_.DisplayName -imatch $filter -or $_.Publisher -imatch $filter -or $_.InstallLocation -imatch $filter}|%{
            [pscustomObject]@{
                DisplayName= $_.DisplayName
                Language = $_.Language
                DisplayVersion = $_.DisplayVersion
                Version = $_.Version
                Publisher = $_.Publisher
                InstallDate = if([string]::IsNullOrEmpty($_.InstallDate)){$null}else{[DateTime]::ParseExact($_.InstallDate,"yyyyMMdd",$null)}
                InstallSource = $_.InstallSource
                InstallLocation = $_.InstallLocation
                UninstallString = $_.UninstallString
                ModifyPath = $_.ModifyPath
                EstimatedSize = $_.EstimatedSize/1KB

            }
        }
    }

}
function Get-ApplicationPath ($name){
    $app = (Get-Command $name -ErrorAction 0).Source
    if($app -eq $null){
        $app = Get-Software ($name -replace '.exe$','') | %{ Get-ChildItem $_.InstallLocation -Filter $name -Recurse | %{ $_.FullName } } |?{ $_ -ne $null }
    }
    return $app
}
function Write-ErrIfAny($msg){
if(-not [string]::IsNullOrEmpty($msg)){
 throw $msg
}
}
function Test-Url($url, $count){
    begin{if($count -eq $null){$count=3}}
    process{
        try{
            $res = Invoke-WebRequest -WebSession $webSession -Method Head -Uri $url

            $ok= $res.StatusCode -in 200,302,301;
            return $ok
        }catch{
            if($_.Exception.Response.StatusCode -eq 401 -and $count -gt 0){
                $global:webSession.UseDefaultCredentials = $false
                $global:webSession.Credentials = $(Get-Credential -Message "[$($count-2)/3] Insert your credentials for $url");
                return Test-Url $url ($count-1)
            }
        }
        return $false
    }
}
function New-ShellLink{
    param ( [string]$SourceExe, [string]$ArgumentsToSourceExe, [string]$DestinationPath)
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($DestinationPath)
    $Shortcut.TargetPath = $SourceExe
    $Shortcut.Arguments = $ArgumentsToSourceExe
    $Shortcut.Save()
}
function Invoke-DownloadFile{
    param(
        [Parameter(Mandatory=$true)]
        $url, 
        [Parameter(Mandatory=$true)]
        $destination, 
        [switch]$includeStats
    )
    $global:downloadCompleted=$false
    $wc = New-Object Net.WebClient
    $wc.UseDefaultCredentials = $Global:webSession.UseDefaultCredentials
    $wc.Credentials = $Global:webSession.Credentials
    $wc.Proxy = $Global:webSession.Proxy

    $file = $url | Split-Path -Leaf
    
    $start = Get-Date 
    $null = Register-ObjectEvent -InputObject $wc -EventName DownloadProgressChanged `
        -MessageData @{start=$start;includeStats=$includeStats;url=$url} `
        -SourceIdentifier WebClient.DownloadProgressChanged -Action { 
            filter Get-FileSize {
	            "{0:N2} {1}" -f $(
	            if ($_ -lt 1kb) { $_, 'Bytes' }
	            elseif ($_ -lt 1mb) { ($_/1kb), 'KB' }
	            elseif ($_ -lt 1gb) { ($_/1mb), 'MB' }
	            elseif ($_ -lt 1tb) { ($_/1gb), 'GB' }
	            elseif ($_ -lt 1pb) { ($_/1tb), 'TB' }
	            else { ($_/1pb), 'PB' }
	            )
            }
            $elapsed = ((Get-Date) - $event.MessageData.start)
            #calculate average speed in Mbps
            $averageSpeed = ($EventArgs.BytesReceived * 8 / 1MB) / $elapsed.TotalSeconds
            $elapsed = $elapsed.ToString('hh\:mm\:ss')
            #calculate remaining time considering average speed
            $remainingSeconds = ($EventArgs.TotalBytesToReceive - $EventArgs.BytesReceived) * 8 / 1MB / $averageSpeed
            $receivedSize = $EventArgs.BytesReceived | Get-FileSize
            $totalSize = $EventArgs.TotalBytesToReceive | Get-FileSize        
            Write-Progress -Activity (" $($event.MessageData.url) {0:N2} Mbps" -f $averageSpeed) `
                -Status ("{0} of {1} ({2}% in {3})" -f $receivedSize,$totalSize,$EventArgs.ProgressPercentage,$elapsed) `
                -SecondsRemaining $remainingSeconds `
                -PercentComplete $EventArgs.ProgressPercentage
            if ($EventArgs.ProgressPercentage -eq 100){
                 Write-Progress -Activity (" $url {0:N2} Mbps" -f $averageSpeed) `
                -Status 'Done' -Completed
                if ($event.MessageData.includeStats.IsPresent){
                    ([PSCustomObject]@{Name='Invoke-DownloadFile';TotalSize=$totalSize;Time=$elapsed}) | Out-Host
                }
            }
            return;
        } 
    $null = Register-ObjectEvent -InputObject $wc -EventName DownloadFileCompleted `
         -MessageData @{destination=$destination;client=$wc} `
         -SourceIdentifier WebClient.DownloadFileCompleted -Action { 
            
            Get-Item $event.MessageData.destination | Unblock-File | Out-Null

            $global:downloadCompleted = $true;

            $event.MessageData.client.Dispose();
            return;
        }  
    try  {  
        $task = $wc.DownloadFileAsync($url, $destination)
        
        while(-not $global:downloadCompleted){
            
            # Waiting end of the download
        }
        
    }  
    catch [System.Net.WebException]  {  
        Write-Error "Download of $url failed" -ErrorAction Stop
    }   
    finally  {    
        $wc.Dispose()
        Unregister-Event -SourceIdentifier WebClient.DownloadProgressChanged -Force | Out-Null
        Unregister-Event -SourceIdentifier WebClient.DownloadFileCompleted -Force | Out-Null
    }  
 }
function Out-FileUtf8NoBOM{
    [cmdletbinding()]
    param(
        [parameter(Position = 0)]
        [string]$path,
        [parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 1)]
        [string]$input        
    )
    Remove-Item $path -Force -ea 0 | out-null
    ""|out-file $path -Force
    [System.IO.File]::WriteAllText($path,$input,[System.Text.Encoding]::ASCII) | out-null
}

## TFS Methods
function Get-TFSContext($collectionUrl){

    $res = Invoke-RestMethod -WebSession $global:webSession `
    "$collectionUrl/_apis/Contribution/HierarchyQuery" `
    -Method Post -Headers @{
        "accept"="application/json;api-version=5.0-preview.1;excludeUrls=true;enumsAsNumbers=true;msDateFormat=true;noArrayWrap=true"
        "content-type"="application/json"  
    } `
    -Body '{"contributionIds":["ms.vss-web.legacy-platform-data-provider"],"dataProviderContext":{"properties":{}}}'

    $webContext = $res.dataProviders.'ms.vss-web.legacy-platform-data-provider'.pageContext.webContext

    return [pscustomobject]@{
        user=$webContext.user
        collection=$webContext.collection
        account=$webContext.account
    }
}
function Get-TFSCurrentUserProfile($url){
    $res = Invoke-RestMethod "$url/_api/_common/GetUserProfile?__v=5" -WebSession $global:webSession -Method Get -ErrorAction 0
    if($res -eq $null){
        throw "Get-TFSCurrentUserProfile::User profile not accessible for the URL: $url"
    }
    return [pscustomobject]@{
        Username = $res.identity.SubHeader
        Email = $res.identity.MailAddress
        DisplayName = $res.identity.FriendlyDisplayName
    }
}
function New-TFSPrivateAccessToken($tfsUrl, $patName){
    ##Get RequestToken
    $pats = Invoke-RestMethod -WebSession $global:webSession "$tfsUrl/_apis/Token/SessionTokens?displayFilterOption=1&createdByOption=3&sortByOption=3&isSortAscending=true&startRowNumber=1&pageSize=100" -Method Get -Headers @{
     "accept"="application/json;api-version=5.0-preview.1;excludeUrls=true;enumsAsNumbers=true;msDateFormat=true;noArrayWrap=true"   
    }
    $pat = $pats | ?{ $_.IsValid -and $_.displayName -eq $patName} | select -first 1

    $context = Get-TFSContext $tfsUrl

    if($pat -ne $null){
        #delete
        Invoke-RestMethod -WebSession $global:webSession "$tfsUrl/_apis/Token/SessionTokens/$($pat.authorizationId)" -Method Delete | Out-Null;
        #prepare the PAT query to renew it
        $pat.authorizationId=[string]::Empty
        $pat.validFrom = Get-Date
        $pat.validTo = (Get-Date).AddYears(1)
        #$pat.accessId = [Guid]::NewGuid().ToString()
        $pat.targetAccounts=[string[]]@($context.collection.id)
        $body = [pscustomobject]@{
            "contributionIds" = [string[]]@("ms.vss-token-web.personal-access-token-issue-session-token-provider")
            "dataProviderContext" = [pscustomobject]@{
                "properties" = [pscustomobject]$pat
            }
        }   

    }else{
        
        $body = [pscustomobject]@{
            "contributionIds" = [string[]]@("ms.vss-token-web.personal-access-token-issue-session-token-provider")
            "dataProviderContext" = [pscustomobject]@{
                "properties" = [pscustomobject]@{
                  "clientId"="00000000-0000-0000-0000-000000000000"
                  "accessId"=[Guid]::NewGuid().ToString()
                  "authorizationId"=""
                  "validFrom" = Get-Date
                  "validTo" = (Get-Date).AddYears(1)
                  "userId" = $null
                  "displayName"=$patName
                  "scope"="vso.code_write vso.packaging_write vso.release_execute vso.profile"
                  "targetAccounts"=[string[]]@($context.collection.id)
                  "token"=$null
                  "alternateToken"=$null
                  "isValid"=$true
                  "isPublic"=$false
                  "publicData"=$null
                  "source"=$null
                  "claims"=$null
                }
            }
        }
    }
    #create PAT
    $resp = Invoke-RestMethod "$tfsUrl/_apis/Contribution/HierarchyQuery" -WebSession $global:webSession -Method Post -Body $($body|ConvertTo-Json -Depth 99 -Compress) -Headers @{
        "accept"="application/json;api-version=5.0-preview.1;excludeUrls=true;enumsAsNumbers=true;msDateFormat=true;noArrayWrap=true"
        "content-type"="application/json"
    }
    
    $res = $resp.dataProviders.'ms.vss-token-web.personal-access-token-issue-session-token-provider'.token
    return $res;
}


## Git Methods
function New-GitCommitMessageTemplate{
    return @"
#######################: 72 Characters :###############################
# Title line
type(scope): subject
# BLANK LINE: Do not add text below.

# Body: explain the propose of that commit to answer the how and why
Your commit message
# BLANK LINE: Do not add text below.

# Footer
# tags: 
#
###########################: HELP :####################################
# # HELP
#
# Lines starting with # are ignored by Git
#
# ## Title line:
#  * Maximum of 72 characters
#  * Do NOT capitalize first letters
#  * Format: <type>(<scope>): <subject>
#    - <type>: cf. table below
#    - (<scope>): optional, specify a place into the repository 
#                 eg. (SolutionName/ComponentName)
#    - <subject> MUST starts with an imperative verbs
#      > add
#      > update
#      > remove
#      > upgrade
#      > downgrade
# 
# |  <type>  |   Description                                          |
# |----------|--------------------------------------------------------|
# | build	 |  Changes affecting the build or external dependencies  |
# | ci       |  Changes to our CI configuration files and scripts\
#               eg. Azure App Configuration, Azure Pipeline           |
# | docs     |  Change performed only on the documentation            |
# | feat     |  Adding a new feature/behavior to the source code      |
# | fix      |  Correct a bug in the source code                      |
# | perf     |  Code changes which improves the performance           |
# | refactor |  Code changes which is not a fix or add a feature      |
# | style    |  Beautifying the source code without build impacts\
#               eg. white-spaces, code formatting...                  |
# | test     |  Adding missing unit tests or fixing an existing one   |
# | revert   |  When a commit must be rolling back.\
#               *Attention*\
#                 - <subject> MUST reuse the subject from the \
#                   previous commit.
#                 - <body> MUST start with:\
#                   'This reverts commit <previous_commit_hash>'      |
#
#
#  ## Body line(-s)
#  * MUST use the imperative, present tense
#  * 
#  * Maximum of 72 characters per line for word wrapping
#  * No line number limits
#
#
#  ## Footer line
#  * Format: tags: <branch_name>[; <INC|ENHCXXXXX>[; <INC|ENHCXXXXX>[; <INC|ENHCXXXXX>]]]
#
"@ -replace '[\r\n]$',''
}
function New-GitHooks{
    $preCommit = 

    return @{
        "commit-msg" = 
{param($repositoryPath, $messagePath)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$global:errorCount = 0;
function Write-Check{
    param([string]$message, [switch]$passed, [switch]$warning)
    $warnOnly = $warning.IsPresent -and $warning.ToBool()
    $ok=$passed.IsPresent -and $passed.ToBool()
    $mark = if($ok){
        @{
            Object = [regex]::Unescape("\u2714")
            ForegroundColor = 'Green'
            NoNewLine = $true
        }
    }else{
        if($warnOnly){
            @{
                Object = [regex]::Unescape("\u26a0")
                ForegroundColor = 'Yellow'
                NoNewLine = $true
            }
        }else{
            @{
                Object = [regex]::Unescape("\u2716")
                ForegroundColor = 'Red'
                NoNewLine = $true
            }
        }
    }
    Write-Host "[ " -NoNewline
    Write-Host @mark
    Write-Host " ] " -NoNewline
    Write-Host $message
    if(-not $ok -and -not $warnOnly){
        $global:errorCount += 1;
    }
}

$currentBranchName = $(git rev-parse --abbrev-ref HEAD)
$currentBranchNameTrimmed = $currentBranchName -replace '^[^\/]+\/',''

#BranchName checks
$pattern="^(master|develop|feature\/(INC|ENHC)\d{5,7}|hotfix\/INC\d{5,7}|bugfix\/.+|release\/CHG\d{5,7})"
Write-Check "The current branch name $currentBranchName follow the pattern -> $pattern" -passed:($currentBranchName -match $pattern)

#Commit Check
$message = Get-Content $messagePath -ErrorAction 0;
if($null -eq $message){$message = ""}
$lines = $message.Split([Environment]::NewLine)
$linesChanged = $false

$firstLine = $lines | Select-Object -First 1

#first line

$pattern="^(?<type>build|ci|docs|feat|fix|perf|refactor|style|test|revert)(?:\((?<scope>[^\)]+)\))?:\s(?<subject>.+)"

## Rewite full Message when git-flow release finish

$mergingCommit = "$(git rev-parse -q --verify MERGE_HEAD)"
$isMerging = $mergingCommit -ne [string]::Empty

if($isMerging -and $firstLine -imatch "^merge branch 'release\/[^']+'(?:\s+)?$"){
    $releaseBranchName = $firstLine -replace "^merge branch '(release\/[^']+)'(?:\s+)?$",'$1'
    $releaseName = $releaseBranchName -replace "[^\/]+\/([^\/]+)$",'$1'
    $firstLine = "build: merge release $releaseName"
    $lines = @(
        $firstLine,
        "",
        "Merge '$releaseBranchName' back to '$currentBranchName with the following:"
    )
    ($(git cherry -v $currentBranchName $releaseBranchName) | Out-String) -split "[\r\n]+" | ?{ -not [string]::IsNullOrEmpty($_) } | %{
        $title = $_ -ireplace '^\+\s[\dabcdef]{40}\s',''

        if($title -imatch $pattern){
            $title = $title -replace $pattern,'${subject}'
        }
        if($title.Length -gt 70){
            $title = $title.SubString(0, 67)+"..."
        }
        $lines+="* $title"
    }
    $lines += ""
    $lines += "`r`n`r`ntags: $releaseName";

    $linesChanged = $true;
}

if($isMerging -and $firstLine -imatch "^merge tag '[^']+'.*"){
    $firstLine = "build: merge tag $($firstLine -replace "^merge tag ('[^']+').*",'$1')"
    $linesChanged = $true;
}

## ends: Rewite full Message when git-flow release finish


$matches = [regex]::Matches($firstLine, $pattern);
Write-Check "Title line follow the pattern -> $pattern" -passed:(-not ($matches -eq $null -or $matches.Count -eq 0))

#second line
Write-Check "The second line is empty" -passed:($($lines | Select-Object -First 1 -Skip 1) -eq "")

# Content lines less than 73 chars
Write-Check "The message lines contains of maximum 72 characters" -passed:($($lines | Where-Object{$_.Length -gt 72}).Count -eq 0)

#Footer line
$footerBlankLine=$($lines | Select-Object -Last 2|Select-Object -First 1) -eq "";
$startTags =($($lines| Select-Object -Last 1) -match "^tags:\s$currentBranchNameTrimmed")
Write-Check "The line before the footer is empty" -passed:$footerBlankLine -warning
Write-Check "The footer starts with required contents -> tags: $currentBranchNameTrimmed" -passed:$startTags -warning

$lastLine = $($lines| Select-Object -Last 1).Trim() -replace ',',';'
$linesChanged = $linesChanged -bor $lastLine -ne $($lines| Select-Object -Last 1).Trim()

if(-not $startTags){
    $linesChanged = $true;
    $lastLine = if($lastLine -match '^(?:[\r\n]+)?tags:'){
        $matches = [regex]::Matches($lastLine, '^(?:[\r\n]+)?tags:(.*)')
        $tagsValue = $matches.Groups.Item(1).Value.Trim()
        "$($lastLine -replace '^([\r\n]+).+','$1')tags: $currentBranchNameTrimmed"+$(if($tagsValue.Length -gt 0){"; $tagsValue"})
    }else{
        "$lastLine`r`n`r`ntags: $currentBranchNameTrimmed"
    }
    write-host "Tags added to the last commit message line"
}
if(-not $footerBlankLine -and $startTags){
    $linesChanged = $true;
    $lastLine = "`r`n$lastLine";
}
if($linesChanged){
    $lines[0]=$firstLine
    $lines[$lines.Length-1]=$lastLine
    [System.IO.File]::WriteAllText($messagePath,$([string]::Join("`r`n",$lines)),[System.Text.Encoding]::ASCII) | out-null
    Write-Host "Commit message updated !"
}

#exit
if($global:errorCount -gt 0){
    write-output "$global:errorCount errors, please make sure your commit message follow guidelines."
}
exit $global:errorCount
}.ToString() 
        "prepare-commit-msg" = 
{param($repositoryPath, $messagePath)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$currentBranchName = $(git rev-parse --abbrev-ref HEAD)
$currentBranchNameTrimmed = $currentBranchName -replace '^[^\/]+\/',''

$revertCommitHash = "$(git rev-parse -q --verify REVERT_HEAD)"
$isReverting = $revertCommitHash -ne ""

#building the message
if($isReverting){
    $firstLine = $(git log --format=%B -n 1 $revertCommitHash).Split([Environment]::NewLine) | Select-Object -First 1
    $firstLine = $firstLine -replace '^build|ci|docs|feat|fix|perf|refactor|style|test|revert'
    $firstLine = $(if($firstLine -match '^\('){""}else{":"})+$firstLine;

    $message=@"
revert$firstLine

This reverts commit $revertCommitHash.

tags: $currentBranchNameTrimmed
"@ -replace '^\s+|\s+$','';

    [System.IO.File]::WriteAllText($messagePath,$message,[System.Text.Encoding]::ASCII) | out-null
}

exit 0}.ToString()
    }

}
function Set-GitGlobalConfig($userDisplayName, $userEmail, [object[]]$UrlTokens){

    $gitBin = Get-ApplicationPath git.exe | select -First 1

    #disable globally SSL Verification checks in case of self-signed certificate
    &$gitbin config --global http.sslVerify false
    &$gitbin config --global user.name "$userDisplayName"
    &$gitbin config --global user.email $userEmail

    $UrlTokens | %{
        $token64 = $([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(":$($_.token)"))).Trim()
        &$gitbin config --global http.$($_.url).extraHeader "Authorization: Basic $token64"
    }


    $usrGitPath = "$env:USERPROFILE\.git"
    mkdir $usrGitPath -Force | out-null

    #set default commit message template
    $templatePath = "$usrGitPath\git_msg_template.txt"
    New-GitCommitMessageTemplate | Out-FileUtf8NoBOM $templatePath

    &$gitbin config --global commit.template "$templatePath"

    
    #Hooks
    $hooksPath = "$usrGitPath\hooks"
    mkdir $hooksPath -Force | out-null
    
    &$gitbin config --global core.hookspath `"~/.git/hooks`"

    $hooks=New-GitHooks
    $hooks.Keys | %{
        "#!/bin/sh`r`npowershell.exe `"-NoProfile`" `"-ExecutionPolicy`" `"RemoteSigned`" `"-File`" `$(echo ~/.git/hooks/$_.ps1) `$(pwd) `$(pwd)'/'`$1 `$2 `$3 `$4 `$5 `$6`r`nexit" | Out-FileUtf8NoBOM "$hooksPath\$_"
        $hooks[$_] | Out-FileUtf8NoBOM "$hooksPath\$_.ps1"
    }

}
function Get-GitOnlineVersions{

    $pattern = if([Environment]::Is64BitOperatingSystem){'Git-\d+\.\d+\.\d+.*-64-bit\.exe$'}else{'Git-\d+\.\d+\.\d+.*-32-bit\.exe$'}

    $res = Invoke-RestMethod https://api.github.com/repos/git-for-windows/git/releases -WebSession $global:webSession

    $res | ?{ -not $_.prerelease } | %{
        [pscustomobject]@{
            version=[Version]($_.name -replace '.+(\d+\.\d+\.\d+)(\((\d+)\))?$','$1.$2' -replace '[\(\)]|\.$')
            url=$_.assets | ?{$_.name -imatch $pattern } | %{ $_.browser_download_url } | select -First 1
        }
    }
}
function Install-Git([bool]$latest){
    begin{
        $versions = Get-GitOnlineVersions;
        $version = $versions | select -First 1
    }
    process{
        if($latest -ne $true){
            Write-Host "Available Git versions: "
            $versions | %{ write-host $(" $(if($version -eq $_){"[*]"}else{"[ ]"}) $($_.version)") }
            $choice = $null
            while($true){
                $choice = $(Read-Host "Which version must be installed ? [$($version.version)]").Trim()
                if([string]::IsNullOrEmpty($choice)){
                    break;
                }
                [Version]$v = $null
                if([Version]::TryParse($choice, [ref]$v)){
                    $x = $versions| ?{ $_.version -eq $v } | select -First 1
                    if($x -ne $null){
                        $version = $x
                        break;
                    }
                }
            }

        }
        
        #Download
        $fileName = Split-Path $version.url -Leaf
        $fileFullName = "$env:TEMP\$fileName"
        Remove-Item $fileFullName -Force -ErrorAction 0;
        ## Buggy with GitHub - https://powershell.org/forums/topic/bits-transfer-with-github/ 
        #Start-BitsTransfer -Source $version.url -Destination $fileFullName

        $wc = New-Object Net.WebClient
        $wc.UseDefaultCredentials = $Global:webSession.UseDefaultCredentials
        $wc.Credentials = $Global:webSession.Credentials
        $wc.Proxy = $Global:webSession.Proxy
        
        Invoke-DownloadFile $version.url $fileFullName

        #Install
        Write-Warning "`tFollow the installation wizard`r`nthen the setup process will continue."
        Start-Sleep -Seconds 2
        $p = Start-Process $fileFullName -PassThru
        do {start-sleep -Milliseconds 500}
        until ($p.HasExited)

    }
}

## Sourcetree Methods
function Set-SourceTreeCredentials([uri]$url,[string]$userEmail, [string]$patToken){
    
    begin{
        $sourcetreeBin = Get-ApplicationPath sourcetree.exe | Sort-Object | select -First 1
        $sourceTreeDirectory = Split-Path $sourcetreeBin
        [Reflection.Assembly]::LoadFrom("$sourceTreeDirectory\SourceTree.Accounts.Windows.dll") | Out-Null
        [Reflection.Assembly]::LoadFrom("$sourceTreeDirectory\SourceTree.Api.UI.Wpf.dll") | Out-Null
        
    }

    process{
        
        $credCategory="sourcetree-rest"
        $credKey = "{0}://{1}{2}{3}" -f 
                        $url.Scheme,
                        $(if([string]::IsNullOrEmpty($userEmail)){[string]::Empty}else{($userEmail -replace '@','_')+"@"}),
                        $url.Host,
                        $(if($url.Authority.Contains(':')){":$($url.Port)"}else{[string]::Empty})

        $credManager = New-Object SourceTree.Accounts.Windows.CredentialManagerSecretManager
        $credManager.SaveSecretByCategory($credCategory,$credKey,$patToken);

        #Write-Verbose "$credKey::$userEmail::$patToken" -Verbose
        #Write-Verbose "Read::$([SourceTree.Utils.StringExtensions]::ToUnsecureString($credManager.ReadSecretByCategory($credCategory, $credKey)))" -Verbose

    }

}
function Set-SourceTreeAccounts([string]$url, $userDisplayName, $userEmail){
    
    begin{
    
        $filePath = "$env:APPDATA\Atlassian\SourceTree\accounts.json"
        [System.Collections.ArrayList]$accounts = $null;

        if(Test-Path $filePath){
           $o = ([object[]](Get-Content $filePath | Out-String | ConvertFrom-Json)) | ?{ $_.HostInstance.BaseUrl -ine $devOpsCollectionUrl }

           if($o.Count -eq 0 -or $o.Count -eq $null){[object[]]$o=@([object]$o)}else{$o=[object[]]$o}

           $accounts = ([System.Collections.ArrayList]$o)|?{[string]::IsNullOrEmpty($_)};
        }

        if($accounts -eq $null -or $accounts.Count -eq 0){
            $accounts = [System.Collections.ArrayList]@(,$([pscustomobject]@{
            "`$id"= "1"
            "`$type"= "SourceTree.Api.Host.Identity.Model.IdentityAccount, SourceTree.Api.Host.Identity"
            "IsDefault"= $false
            "Authenticate"= $true
            "HostInstance"= [pscustomobject]@{
                "`$id"= "2"
                "`$type"= "SourceTree.Host.Bitbucket.BitbucketInstance, SourceTree.Host.Bitbucket"
                "Host"=[pscustomobject]@{
                    "`$id"= "3"
                    "`$type"= "SourceTree.Host.Bitbucket.BitbucketHost, SourceTree.Host.Bitbucket"
                    "Id"= "bitbucket"
                }
                "BaseUrl" = "https://bitbucket.org/"
                "Protocol"= "HTTPS"
            }
            "Credentials" = [pscustomobject]@{
                "`$id"= "4"
                "`$type"= "SourceTree.Api.Account.OAuth.TwoZero.OAuthTwoZeroCredentials, SourceTree.Api.Account.OAuth.TwoZero"
                "Username"= ""
                "AuthenticationScheme" = [pscustomobject]@{
                    "`$type"="SourceTree.Api.Account.OAuth.TwoZero.OAuthTwoZeroBearerAuthenticationScheme, SourceTree.Api.Account.OAuth.TwoZero"
                    "Value"= "Personal Access Token"
                    "Name"= "OAuth"
                    "Description"= "OAuth Token"
                    "HeaderValuePrefix"= "Bearer"
                    "UsernameIsRequired"= $false
                }
                "EmailHash"= $null
                "DisplayName"= ""
                "AvatarURL" = $null
                "Id" = $null
                "Email" = $null
            }
        }))
        }

        ### Get last json Id
        $script:lastId = [int](
            (@($accounts.'$id')+($accounts|Get-Member -ErrorAction 0|%{$accounts.($_.Name).'$id'})
            )|?{-not[string]::IsNullOrEmpty($_) -and -not [string]::IsNullOrWhiteSpace($_)}|Sort-Object -Descending |select -First 1
        )
        
        function nextId{
            $script:lastId+=1
            $script:lastId.ToString()
        }

    }
    process{

        $accounts.Add($([pscustomobject]@{
            "`$id"= nextId
            "`$type"= "SourceTree.Model.ScmAccount, SourceTree.Api.Host.Scm"
            "IsDefault"= $false
            "Authenticate"= $true
            "HostInstance"= [pscustomobject]@{
                "`$id"= nextId
                "`$type"= "Sourcetree.Host.Msft.TeamServices.VstsHostInstance, Sourcetree.Host.Msft.TeamServices"
                "Host"=[pscustomobject]@{
                    "`$id"= nextId
                    "`$type"= "Sourcetree.Host.Msft.TeamServices.VstsHost, Sourcetree.Host.Msft.TeamServices"
                    "Id"= "vsts"
                }
                "BaseUrl" = $url
                "Protocol"= "HTTPS"
            }
            "Credentials" = [pscustomobject]@{
                "`$id"= nextId
                "`$type"= "Sourcetree.Api.Account.Pat.PersonalAccessTokenCredentials, Sourcetree.Api.Account.Pat"
                "Username"= $userEmail
                "AuthenticationScheme" = [pscustomobject]@{
                    "`$type"="Sourcetree.Api.Account.Pat.PersonalAccessTokenAuthenticationScheme, Sourcetree.Api.Account.Pat"
                    "Value"= "Personal Access Token"
                    "Name"= "Personal Access Token"
                    "Description"= "Personal Access Token"
                    "HeaderValuePrefix"= "Personal Access Token"
                    "UsernameIsRequired"= $false
                }
                "EmailHash"= $null
                "DisplayName"= $userDisplayName
                "AvatarURL" = $null
                "Id" = $null
                "Email" = $null
            }
        })) | Out-Null
       
       $accounts|ConvertTo-Json -Depth 99 |Out-File $filePath -Encoding utf8
        
    }

}
function Set-SourceTreeUserSettings($userDisplayName, $userEmail){
    begin{
        $gitBin = Get-ApplicationPath git.exe | select -First 1
        $sourcetreeBin = Get-ApplicationPath sourcetree.exe | Sort-Object | select -First 1
        $sourceTreeDirectory = Split-Path $sourcetreeBin
        [Reflection.Assembly]::LoadFrom("$sourceTreeDirectory\SourceTree.Accounts.Windows.dll") | Out-Null
        [Reflection.Assembly]::LoadFrom("$sourceTreeDirectory\SourceTree.Api.UI.Wpf.dll") | Out-Null

        $sourceTreeUserConfig = (Get-ChildItem -Filter 'user.config' -Recurse $env:LOCALAPPDATA\Atlassian).FullName |Sort-Object|select -First 1

        $configManager = New-Object SourceTree.Configuration.DefaultConfigurationManager
        $licenseManager = New-Object SourceTree.Licence.DefaultLicenceManager $configManager
        
        
        $ClientConfigPathsType = [System.Configuration.ConfigurationManager].Assembly.GetType("System.Configuration.ClientConfigPaths")

        $_roamingConfigDirectoryField = $ClientConfigPathsType.GetField("_roamingConfigDirectory", [System.Reflection.BindingFlags]"Instance,NonPublic")
        $_roamingConfigFilenameField = $ClientConfigPathsType.GetField("_roamingConfigFilename", [System.Reflection.BindingFlags]"Instance,NonPublic")
        $_localConfigDirectoryField = $ClientConfigPathsType.GetField("_roamingConfigDirectory", [System.Reflection.BindingFlags]"Instance,NonPublic")
        $_localConfigFilenameField = $ClientConfigPathsType.GetField("_localConfigFilename", [System.Reflection.BindingFlags]"Instance,NonPublic")
        $_applicationUriField =  $ClientConfigPathsType.GetField("_applicationUri", [System.Reflection.BindingFlags]"Instance,NonPublic")
        $_applicationConfigUriField =  $ClientConfigPathsType.GetField("_applicationConfigUri", [System.Reflection.BindingFlags]"Instance,NonPublic")

        $s_current=$ClientConfigPathsType.GetField("s_current",[System.Reflection.BindingFlags]"Static,NonPublic").GetValue($null)

        $clientConfigPaths=[pscustomobject]@{
            PreviousRoamingConfigDirectory=$null
            PreviousRoamingConfigFilename=$null
            PreviousLocalConfigDirectory=$null
            PreviousLocalConfigFilename=$null
            PreviousApplicationUri=$null
            PreviousApplicationConfigUri=$null
        }
        Add-Member -InputObject $clientConfigPaths -Name RoamingConfigDirectory -MemberType ScriptProperty -Value { $_roamingConfigDirectoryField.GetValue($s_current) } -SecondValue {param($value) $this.PreviousRoamingConfigDirectory = $_roamingConfigDirectoryField.GetValue($s_current); $_roamingConfigDirectoryField.SetValue($s_current,$value); }
        Add-Member -InputObject $clientConfigPaths -Name RoamingConfigFilename -MemberType ScriptProperty -Value { $_roamingConfigFilenameField.GetValue($s_current) } -SecondValue {param($value) $this.PreviousRoamingConfigFilename = $_roamingConfigFilenameField.GetValue($s_current); $_roamingConfigFilenameField.SetValue($s_current,$value); }
        Add-Member -InputObject $clientConfigPaths -Name LocalConfigDirectory -MemberType ScriptProperty -Value { $_localConfigDirectoryField.GetValue($s_current) } -SecondValue {param($value) $this.PreviousLocalConfigDirectory = $_localConfigDirectoryField.GetValue($s_current); $_localConfigDirectoryField.SetValue($s_current,$value); }
        Add-Member -InputObject $clientConfigPaths -Name LocalConfigFilename -MemberType ScriptProperty -Value { $_localConfigFilenameField.GetValue($s_current) } -SecondValue {param($value) $this.PreviousLocalConfigFilename = $_localConfigFilenameField.GetValue($s_current); $_localConfigFilenameField.SetValue($s_current,$value); }
        Add-Member -InputObject $clientConfigPaths -Name ApplicationUri -MemberType ScriptProperty -Value { $_applicationUriField.GetValue($s_current) } -SecondValue {param($value) $this.PreviousApplicationUri = $_applicationUriField.GetValue($s_current); $_applicationUriField.SetValue($s_current,$value); }
        Add-Member -InputObject $clientConfigPaths -Name ApplicationConfigUri -MemberType ScriptProperty -Value { $_applicationConfigUriField.GetValue($s_current) } -SecondValue {param($value) $this.PreviousApplicationConfigUri = $_applicationConfigUriField.GetValue($s_current); $_applicationConfigUriField.SetValue($s_current,$value); }
        
        Add-Member -InputObject $clientConfigPaths -Name RestorePrevious -MemberType ScriptMethod -Value {
            Get-Member -InputObject $this -MemberType NoteProperty | ?{$_.Name -imatch 'previous'} | %{
                if(-not [string]::IsNullOrEmpty($this.($_.Name))){
                    $this.($($_.Name -replace 'Previous','')) = $this.($_.Name)
                    $this.($_.Name) = $null
                }
            }
        }
    }
    process{

        
        try{
            
            $clientConfigPaths.RoamingConfigFilename = $sourceTreeUserConfig
            $clientConfigPaths.RoamingConfigDirectory = Split-Path $sourceTreeUserConfig
            $clientConfigPaths.LocalConfigFilename = $sourceTreeUserConfig -replace '\\Roaming\\','\Local\'
            $clientConfigPaths.LocalConfigDirectory = Split-Path $clientConfigPaths.LocalConfigFilename
            $clientConfigPaths.ApplicationUri = $sourcetreeBin
            $clientConfigPaths.ApplicationConfigUri = "$sourcetreeBin.config"

            $allSettings = [SourceTree.Properties.Settings]::Default
            $allSettings.FirstLaunchSinceHgAdded = $false;
            $allSettings.FirstLaunch=$false;
            $allSettings.AgreedToEULA = $true;
            $allSettings.AgreedToEULAVersion = $licenseManager.EulaVersion;
            $allSettings.DefaultEmail = $userDisplayName;
            $allSettings.DefaultFullName = $userDisplayName;
            $allSettings.Save()

        }finally{
            $clientConfigPaths.RestorePrevious()
        }

    }
}
function Remove-SourceTreeSSLVerification{
    
    begin{
        $sourcetreeBin = Get-ApplicationPath sourcetree.exe | Sort-Object | select -First 1
        $sourceTreeExeConfig = "$sourcetreeBin.config"

        [xml]$confDocument = Get-Content $sourceTreeExeConfig
    }

    process{
        
        $sysNode = $confDocument.DocumentElement.SelectSingleNode("system.net");
        if($sysNode -eq $null){
            $sysNode = $confDocument.CreateElement("system.net");
            $confDocument.configuration.AppendChild($sysNode) | out-null
        }
        $spmNode = $sysNode.SelectSingleNode('settings/servicePointManager');
        if($spmNode -eq $null){
            $settingsNode = $sysNode.settings
            if($sysNode.settings -eq $null){
                $settingsNode = $confDocument.CreateElement("settings")
                $sysNode.AppendChild($settingsNode)  | out-null
            }
            $spmNode = $confDocument.CreateElement("servicePointManager");
            $settingsNode.AppendChild($spmNode)  | out-null
        }

        $spmNode.SetAttribute("checkCertificateName","false");
        $spmNode.SetAttribute("checkCertificateRevocationList","false");
        
        $confDocument.Save($sourceTreeExeConfig)

        #$Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
        #[System.IO.File]::WriteAllLines($sourceTreeExeConfig, $confDocument.OuterXml, $Utf8NoBomEncoding)
    }

}
function Get-SourceTreeOnlineVersions{
    
    $res = Invoke-WebRequest https://www.sourcetreeapp.com/download-archives -UseDefaultCredentials -WebSession $global:webSession

    $matches = [regex]::Matches($res.RawContent,'"(?<url>https?:\/\/[^"]+\/[^"]+-(?<version>\d+\.\d+\.\d+)\.exe)"',[System.Text.RegularExpressions.RegexOptions]"IgnoreCase,Multiline,ECMAScript")

    $matches | %{
        [pscustomobject]@{
            version=[Version]$_.Groups['version'].Value
            url=$_.Groups['url'].Value
        }
    } | sort -Property version -Descending -Unique
}
function Install-SourceTree([bool]$latest){
    begin{
        $versions = Get-SourceTreeOnlineVersions;
        $version = $versions | select -First 1
    }
    process{
        if($latest -ne $true){
            Write-Host "Available Sourcetree versions: "
            $versions | %{ write-host $(" $(if($version -eq $_){"[*]"}else{"[ ]"}) $($_.version)") }
            $choice = $null
            while($true){
                $choice = $(Read-Host "Which version must be installed ? [$($version.version)]").Trim()
                if([string]::IsNullOrEmpty($choice)){
                    break;
                }
                [Version]$v = $null
                if([Version]::TryParse($choice, [ref]$v)){
                    $x = $versions| ?{ $_.version -eq $v } | select -First 1
                    if($x -ne $null){
                        $version = $x
                        break;
                    }
                }
            }

        }
        
        if(Test-Path "$env:LOCALAPPDATA\SourceTree"){
            Remove-Item "$env:LOCALAPPDATA\SourceTree" -Force -ErrorAction 0
        }

        #Download
        $fileName = Split-Path $version.url -Leaf
        $fileFullName = "$env:TEMP\$fileName"
        Remove-Item $fileFullName -Force -ErrorAction 0;
        Invoke-DownloadFile $version.url $fileFullName

        #Install
        Write-Warning "`tFollow the installation wizard, when you arrive at the step to register, close the installation wizard`r`nthen the setup process will continue."
        Start-Sleep -Seconds 2
        $p = Start-Process $fileFullName -PassThru
        do {start-sleep -Milliseconds 500}
        until ($p.HasExited)
        #Start-Sleep -Seconds 5
        kill -Name pageant -ErrorAction 0 -Force

    }
}
function Complete-SourceTreeInstallation{

    $sourcetreeBin = Get-ApplicationPath sourcetree.exe | Sort-Object | select -First 1

    #Shortcuts installation/update

    
    ##StartMenu & Desktop & StartUp Menu
    @(
        [System.Environment]::GetFolderPath("DesktopDirectory")
        ,([System.Environment]::GetFolderPath("StartMenu")+"\Programs\Atlassian")
    ) |%{
    
        if(-not (Test-Path $_)){
            mkdir $_ -Force | out-null
        }

        $lnkFullName = "{0}\SourceTree.lnk" -f $_

        (New-ShellLink $sourcetreeBin "" $lnkFullName) | out-null
    
    }

}



## MAIN
function main{
    #Ensure SSL Verification is disabled in case the certificate is self-signed
    Disable-CertificateChecks

    #Initialize Global variables
    $global:webSession =  New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $global:webSession.UseDefaultCredentials = $true
    $global:webSession.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
    
    Write-Host "Main::Starts"
    
    #Check SourceTree & Git Installed
    $errMessage="";
    $gitBin = Get-ApplicationPath git.exe | select -First 1
    $sourcetreeBin = Get-ApplicationPath sourcetree.exe | Sort-Object | select -First 1
    
    if($gitBin -eq $null){
        $a = Read-Host "Would you install Git for Windows ? [y/N]"
        if($a -ieq 'y'){
            Install-Git
        }else{
            $errMessage = "Main::InitCheck::GIT for Windows is not installed!`r`nPLease install the latest version from: https://git-scm.com/download/win"
        }
    }else{
        Write-Host "Main::InitCheck::Git Installed at that location: $gitBin"
    }

    if($sourcetreeBin -eq $null){
        $a = Read-Host "Would you install SourceTree ? [y/N]"
        if($a -ieq 'y'){
            Install-SourceTree
        }else{
            $errMessage = "`r`nMain::InitCheck::SourceTree is not installed!`r`nPlease install the latest version for Windows from: https://www.sourcetreeapp.com"
        }
    }else{
        Write-Host "Main::InitCheck::SourceTree Installed at that location: $sourcetreeBin"
    }
    Write-ErrIfAny $errMessage

    #Ensure shortcuts are available
    Complete-SourceTreeInstallation
    Write-Host "Main::SourceTree shortcuts restored"


    #Check TFS Url is working, if any insert credentials
    if(Test-Url $devOpsCollectionUrl){
        Write-Host "Main::InitCheck::AzureDevOps Server is reachable at that address: $devOpsCollectionUrl"
    }else{
        Write-ErrIfAny "Main::InitCheck::AzureDevOps Server is NOT reachable at that address: $devOpsCollectionUrl`r`nPlease, check the network connectivity and the credentials"
    }

    #Get TFS User Profile
    $tfsContext = Get-TFSContext $devOpsCollectionUrl
    $tfsCurrentUserProfile = $tfsContext.user

    Write-Host "Main::AzureDevops User : $($tfsCurrentUserProfile.name)"
    Write-Host "Main::AzureDevops Project Collection Name : $($tfsContext.collection.name)"
    Write-Host "Main::AzureDevops Project Collection ID : $($tfsContext.collection.id)"

    #Get New or Renew a Private Access Token fro the current user in order to setup Git and Sourcetree for automating the authentication
    $tfsPrivateAccessToken = New-TFSPrivateAccessToken $devOpsCollectionUrl $defaultPatName
    if($tfsPrivateAccessToken -ne $null){
        Write-Host "Main::New AzureDevops Private Access Token is generated for the project collection"
    }else{
        throw "Main::AzureDevops Private Access Token cannot be generated due to an unexpected error."
    }

    #Setup Git Global Settings
    Set-GitGlobalConfig $tfsCurrentUserProfile.name $tfsCurrentUserProfile.email @([pscustomobject]@{
        url=$devOpsCollectionUrl
        token=$tfsPrivateAccessToken
    })
    Write-Host "Main::Git global config up-to-date"

    #Setup SourceTree
    Set-SourceTreeUserSettings $tfsCurrentUserProfile.name $tfsCurrentUserProfile.email
    Write-Host "Main::Sourcetree - User settings updated for $($tfsCurrentUserProfile.name)"

    Set-SourceTreeAccounts $devOpsCollectionUrl $tfsCurrentUserProfile.name $tfsCurrentUserProfile.email
    Write-Host "Main::Sourcetree - AzureDevops account added for $devOpsCollectionUrl"

    Set-SourceTreeCredentials $devOpsCollectionUrl $tfsCurrentUserProfile.email $tfsPrivateAccessToken
    Write-Host "Main::Sourcetree credentials added/updated for the AzureDevops account"

    Remove-SourceTreeSSLVerification
    Write-Host "Main::Sourcetree - SSL Verification disabled"

    Write-Host "Main::Ends"

}

try{
    main
}finally{

}