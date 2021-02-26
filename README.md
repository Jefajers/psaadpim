# PSAADPIM Documentation
This asset is aimed at enabling Azure AD Priviliged Identity Management enrolment and initalt role setup. Ideally used as a supporting back-end function during new Azure subscription creation.
Main target scenarios for this PowerShell function library and supporting wrapper script:
- Azure Subscription enrolment into Azure AD PIM
- Set Azure AD PIM Role Settings for Azure resources according to function baseline
- Add Azure AD Groups as members of Azure roles controlled by Azure AD PIM 
## Prerequisites
- PowerShell
- Azure AD PIM license
- Azure subscription to host the back-end service
- Azure resource group
- Dedicated service accounts (one Azure AD User Account and one SPN) to perform the highly privliged PIM actions. Enusre the identiies have the following permission:
    - Azure AD User Account:
        - Assign Azure AD Role "Privileged Role administrator"
        - Assign Azure "User Access Administrator" role assigned on applicable Azure scope depening on your management group structure, recommendation: apply at root level.
    - SPN (modules assume SPN will authenticate with Secret not Certificate):
        - Assign Azure "Reader" role assigned on applicable Azure scope depening on your management group structure, recommendation: apply at root level.
        - Azure Active Directory Graph
            - **Directory.Read.All** of Type:**Application**
        - Microsoft Graph
            - **Group.Read.All** of Type: **Delegated**
            - **PrivilegedAccess.ReadWrite.AzureResources** of Type: **Delegated**
            - **PrivilegedAccess.ReadWrite.AzureAD** of Type: **Delegated** *(optional future proofing)*
            - **PrivilegedAccess.ReadWrite.AzureADGroup** of Type: **Delegated** *(optional future proofing)*
            - **Directory.Read.All** of Type: **Delegated** and **Application** *(optional future proofing)*
### Getting Started
1. [![Deploy To Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.svg?sanitize=true)](https://ms.portal.azure.com/?feature.customportal=false#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FJefajers%2Fpsaadpim%2Fmaster%2Farm%2Fdeploy.json)
1. Add the following modules into the Azure Automation Account
    1. Az.Accounts
    1. Az.Automation
    1. Az.Resources
    1. Microsoft.Graph.Authentication
    1. Microsoft.Graph.Groups
1. Update the newly created Azure Automation Credential objects
    1. For credential: "pimusersvc"
        1. As username enter the user service account upn you have created for this service serviceaccountname@yourtenantname.onmicrosoft.com
        2. As password enter your secret password as the password
    1. For credential: "pimspnsvc"
        1. As username enter the spn service account client id you have created for this service xxxx-xxxx-xxxx-xxxx
        1. As password enter your secret as the password
#### Trigger a job with Az.Automation
- In PowerShell create the following objects as input parameters for the runbook job (remember to add your aad group id, azrole id, rg name and automation account name):
    - `$AADGROUPS  = @(
                @{ ObjectId="<InsertAADGroupID>"}
        )`
    - `$AZROLEDEFIDS  = @(
                    @{ Id="<InsertAzureRoleID>"}
        )`
    - `$AADGROUPS = ConvertTo-Json -InputObject $AADGROUPS`
    - `$AZROLEDEFIDS = ConvertTo-Json -InputObject $AZROLEDEFIDS`
    - `$params = @{"AZSUBSCRIPTIONID"="<EnterAzSubId>";"AADGROUPS"="$AADGROUPS";"ROLEPROFILE"="LightProfile";"AZROLEDEFIDS"="$AZROLEDEFIDS";"ASSIGNMENTTYPE"="Eligible"}`
- Submit the job to the Azure Automation Runbook
    - `Start-AzAutomationRunbook -Name Script -ResourceGroupName <InsertRGName> -AutomationAccountName psaadpim-aa -Parameters $params`
##### The syntax?
- Discover more about the syntax of the Script.ps1 wrapper by examining the synopsis in that file
- Discover more about the syntax of the PSAADPim.ps1 functions by examining the synopsis in that file but start with the Script.ps1 file