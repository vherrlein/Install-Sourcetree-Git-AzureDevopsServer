# Sourcetree Installation Automation

The objective of that PowerShell script is automating the installation by downloading the following products from Web and the setup them for an integration with AzureDevops Servers 2019:
- Git for Windows
- Atlassian Sourcetree

## Process

1. Check Git for Windows is installed
  - If not installed and authozied by the end-user, installing it from internet
2. Check Atlassian Sourcetree is installed
  - If not installed and authozied by the end-user, installing it from internet
3. Recover Sourcetree sortcuts on the desktop and the start menu
4. Retreive the current User Profile from the Azure Devops Server 2019
5. Generate a new Private Access Token for Azure Devops Server
6. Configure Git global settings with the user diaplayname, email, extra headers with the PAT and disabling the SSL verification
7. Configure Sourcetree User Settings (EULA Agreement, Default User email and Default User Name)
8. Configure Sourcetree Account (Default flase Atlassian and the Azure Devops one)
9. Ensure Creadentials for the Azure Devops url is recorded by Windows Credential Manager
10. Disable Sourcetree SSL verification

## Requirements

OS : Windows 10 / Windows Server 2012 R2
Network: Access to internet and the target AzureDevops Server 2019
Admin Priviledge: Not required

## Script configuration

Open the script "SetupSourceTree.ps1" and update the url of your Azure Devops Server with the variable "$devOpsCollectionUrl".

## Script Execution

If your machine is able to run PowerShell script without security restriction policies:

> PS:\> .\SetupSourceTree.ps1

Otherwise Open Microsoft PowerShell ISE with the script file and select all script content then press F8.
