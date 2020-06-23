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
- Service account (Azure AD User Account) with "User Access Administrator" role assigned on applicable Azure scope depening on your management group structure
### Getting Started
1. |[![Deploy To Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.svg?sanitize=true)](https://ms.portal.azure.com/?feature.customportal=false#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FJefajers%2Fpsaadpim%2Fmaster%2arm%2Fdeploy.json) |
1. Add the following modules into the Azure Automation Account
    1. AzureADPreview
    1. Az.Accounts
    1. Az.Automation
    1. Az.Resources
1. Update the newly created Azure Automation Credential with name "pimsvc", as user name enter the service account you have created for this service serviceaccountname@yourtenantname.onmicrosoft.com with your secret password as the password
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
    - `Start-AzAutomationRunbook -Name Script -ResourceGroupName <InsertRGName> -AutomationAccountName <InsertAAName> -Parameters $params`
##### The syntax?
- Discover more about the syntax of the Script.ps1 wrapper by examining the synopsis in that file
- Discover more about the syntax of the PSAADPim.ps1 functions by examining the synopsis in that file but start with the Script.ps1 file