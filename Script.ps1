<#
.SYNOPSIS
    PowerShell function library with supporting wrapper script to enable:
    *Azure Subscription enrolment into Azure AD PIM
    *Set Azure AD PIM Role Settings for Azure resources according to function baseline
    *Add Azure AD Groups as members of Azure roles controlled by Azure AD PIM
.PARAMETER azsubscriptionid
    The Azure subscription id in the following format (GUID): xxxx-xxxx-xxxx-xxxx
    Can be collected by running Get-AzSubscription and look for the ID matching the subscription that matches desired scope
.PARAMETER azroledefids
    The Azure role definition id that PIM should baseline in the following format (json):[{"Id":"xxxx-xxxx-xxxx-xxxx"},{"Id":"xxxx-xxxx-xxxx-xxxx"}]
    Can be collected by running Get-AzRoleDefinition and look for the ID matching the role that matches desired scope
.PARAMETER roleprofile
    This defines which set of profile settings to apply cross all three available dimensions in the following format(string): mediumprofile
.PARAMETER aadgroups
    The Azure AD group object id in the following format (json):[{"ObjectId":"xxxx-xxxx-xxxx-xxxx"},{"ObjectId":"xxxx-xxxx-xxxx-xxxx"}]
    Can be collected by running Get-AzureADGroup and look for the ID matching the group that matches desired scope
.PARAMETER onlyaddaadgroups
    This parameter is optional and used to indicate if the job should skip the role setting stage.
    When this parameter is set to $true the job will still try to onboard the subscription but skip the role setting stage and immediately start adding group to role.
.PARAMETER assignmenttype
    The assignmenttype indicates if the group should be added as Eligible or Active (parameter is case sensitive)
.EXAMPLE
    Using AZ modules to submit a job containing two az roles and two groups.
    $AZROLEDEFIDS = @(
                        @{ Id="xxxx-xxxx-xxxx-xxxx"},
                        @{ Id="xxxx-xxxx-xxxx-xxxx"}
    )
    $AADGROUPS = @(
                    @{ ObjectId="xxxx-xxxx-xxxx-xxxx"},
                    @{ ObjectId="xxxx-xxxx-xxxx-xxxx"}
        )
    $AADGROUPS = ConvertTo-Json -InputObject $AADGROUPS
    $AZROLEDEFIDS = ConvertTo-Json -InputObject $AZROLEDEFIDS
    $params = @{"AZSUBSCRIPTIONID"="xxxx-xxxx-xxxx-xxxx";"AADGROUPS"="$AADGROUPS";"ROLEPROFILE"="LightProfile";"AZROLEDEFIDS"="$AZROLEDEFIDS";"ASSIGNMENTTYPE"="Eligible"}
    Start-AzAutomationRunbook -Name yourrunbookname -AutomationAccountName yourautomationaccountname -ResourceGroupName yourautomationaccountrgname  -Parameters $params

    Script syntax
    .\Script.ps1 -azsubscriptionid xxxx-xxxx-xxxx-xxxx -azroledefids [{"Id":"xxxx-xxxx-xxxx-xxxx"},{"Id":"xxxx-xxxx-xxxx-xxxx"}] -roleprofile mediumprofile -aadgroups [{"ObjectId":"xxxx-xxxx-xxxx-xxxx"},{"ObjectId":"xxxx-xxxx-xxxx-xxxx"}] -assignmenttype Eligible
.OUTPUTS
    N/A
#>
#requires -modules Az.Accounts
#requires -modules Az.Automation
#requires -modules Az.Resources
#requires -modules Microsoft.Graph.Authentication
#requires -modules Microsoft.Graph.Groups

#Parameters
[CmdletBinding(SupportsShouldProcess = $true)]
Param
(
    [Parameter (Mandatory = $true)]
    [guid] $azsubscriptionid,
    [Parameter (Mandatory = $true)]
    [array] $azroledefids,
    [Parameter (Mandatory = $true)]
    [ValidateSet("mediumprofile", "lightprofile")]
    [string] $roleprofile,
    [Parameter (Mandatory = $true)]
    [array] $aadgroups,
    [Parameter (Mandatory = $false)]
    [switch] $onlyaddaadgroups,
    [Parameter (Mandatory = $true)]
    [ValidateSet("Eligible", "Active", IgnoreCase = $false)]
    [string] $assignmenttype
)
#Error Action Preference
$ErrorActionPreference = "Continue"
#Import functions
. .\PSAADPim.ps1
<#
#################
#Profile section#
#################
The three settings dimensions:
1)AdminEligibleSettings are assignment settings for eligible assignments
2)AdminmemberSettings are assignment settings for active assignments
3)UserMemberSettings are activation settings
#>
<#MediumProfile:
Allows permanent eligible assignment
Requires MFA for eligible users
#>
$MediumProfile = @(
    [pscustomobject]@{ "adminEligibleSettings" = @( @{ "ruleIdentifier" = "ExpirationRule"; "setting" = '{"permanentAssignment":true,"maximumGrantPeriodInMinutes":525600}' } ) },
    [pscustomobject]@{ "adminEligibleSettings" = @( @{ "ruleIdentifier" = "MfaRule"; "setting" = '{"mfaRequired":false}' } ) },
    [pscustomobject]@{ "adminMemberSettings" = @( @{ "ruleIdentifier" = "ExpirationRule"; "setting" = '{"permanentAssignment":false,"maximumGrantPeriodInMinutes":259200}' } ) },
    [pscustomobject]@{ "adminMemberSettings" = @( @{ "ruleIdentifier" = "MfaRule"; "setting" = '{"mfaRequired":false}' } ) },
    [pscustomobject]@{ "adminMemberSettings" = @( @{ "ruleIdentifier" = "JustificationRule"; "setting" = '{"required":true}' } ) },
    [pscustomobject]@{ "userMemberSettings" = @( @{ "ruleIdentifier" = "ExpirationRule"; "setting" = '{"permanentAssignment":true,"maximumGrantPeriodInMinutes":480}' } ) },
    [pscustomobject]@{ "userMemberSettings" = @( @{ "ruleIdentifier" = "MfaRule"; "setting" = '{"mfaRequired":true}' } ) },
    [pscustomobject]@{ "userMemberSettings" = @( @{ "ruleIdentifier" = "JustificationRule"; "setting" = '{"required":true}' } ) },
    [pscustomobject]@{ "userMemberSettings" = @( @{ "ruleIdentifier" = "TicketingRule"; "setting" = '{"ticketingRequired":false}' } ) },
    [pscustomobject]@{ "userMemberSettings" = @( @{ "ruleIdentifier" = "ApprovalRule"; "setting" = '{"Approvers":[]}' } ) },
    [pscustomobject]@{ "userMemberSettings" = @( @{ "ruleIdentifier" = "AcrsRule"; "setting" = '{"acrsRequired":false,"acrs":null}' } ) }
)
<#LightProfile:
Allows permanent eligible assignment
Allows permanent active assignment
Requires MFA for eligible users
#>
$LightProfile = @(
    [pscustomobject]@{ "adminEligibleSettings" = @( @{ "ruleIdentifier" = "ExpirationRule"; "setting" = '{"permanentAssignment":true,"maximumGrantPeriodInMinutes":525600}' } ) },
    [pscustomobject]@{ "adminEligibleSettings" = @( @{ "ruleIdentifier" = "MfaRule"; "setting" = '{"mfaRequired":false}' } ) },
    [pscustomobject]@{ "adminMemberSettings" = @( @{ "ruleIdentifier" = "ExpirationRule"; "setting" = '{"permanentAssignment":true,"maximumGrantPeriodInMinutes":259200}' } ) },
    [pscustomobject]@{ "adminMemberSettings" = @( @{ "ruleIdentifier" = "MfaRule"; "setting" = '{"mfaRequired":false}' } ) },
    [pscustomobject]@{ "adminMemberSettings" = @( @{ "ruleIdentifier" = "JustificationRule"; "setting" = '{"required":true}' } ) },
    [pscustomobject]@{ "userMemberSettings" = @( @{ "ruleIdentifier" = "ExpirationRule"; "setting" = '{"permanentAssignment":true,"maximumGrantPeriodInMinutes":480}' } ) },
    [pscustomobject]@{ "userMemberSettings" = @( @{ "ruleIdentifier" = "MfaRule"; "setting" = '{"mfaRequired":true}' } ) },
    [pscustomobject]@{ "userMemberSettings" = @( @{ "ruleIdentifier" = "JustificationRule"; "setting" = '{"required":true}' } ) },
    [pscustomobject]@{ "userMemberSettings" = @( @{ "ruleIdentifier" = "TicketingRule"; "setting" = '{"ticketingRequired":false}' } ) },
    [pscustomobject]@{ "userMemberSettings" = @( @{ "ruleIdentifier" = "ApprovalRule"; "setting" = '{"Approvers":[]}' } ) },
    [pscustomobject]@{ "userMemberSettings" = @( @{ "ruleIdentifier" = "AcrsRule"; "setting" = '{"acrsRequired":false,"acrs":null}' } ) }
)
####################
#Connection section#
####################
try {
    #Connecting to Azure (at the time of writing backend supports User Accounts only)
    Write-Output -InputObject "Connecting to required Azure resources"
    Connect-PimAz -AzAutomationCredentialUserName pimusersvc -AzAutomationCredentialSPNName pimspnsvc -AzADTenant pimtenantid
}
catch {
    Write-Error -Message $_
    break
}
###################
#Execution section#
###################
try {
    #Convert input from json to ensure PowerShell can process it correct, AA has changed behaviour.
    Write-Output -InputObject "Converting Azure Roledefinitionid's to json"
    $azroledefids = $azroledefids | ConvertTo-Json
    Write-Output -InputObject "Converting Azure Roledefinitionid's from json"
    $azroledefids = $azroledefids | ConvertFrom-Json
    Write-Output -InputObject "Converting Azure ActiveDirectory Group id's to json"
    $aadgroups = $aadgroups | ConvertTo-Json
    Write-Output -InputObject "Converting Azure ActiveDirectory Group id's from json"
    $aadgroups = $aadgroups | ConvertFrom-Json
}
catch {
    Write-Error -Message $_
    break
}
try {
    #Set role profile to use based on input
    if ($roleprofile -eq 'mediumProfile') {
        Write-Output -InputObject "settingprofile value to: MediumProfile"
        $settingsprofile = $MediumProfile
    }
    if ($roleprofile -eq 'lightProfile') {
        Write-Output -InputObject "settingprofile value to: LightProfile"
        $settingsprofile = $LightProfile
    }
}
catch {
    Write-Error -Message $_
    break
}
try {
    #Enrol subscription for Azure AD PIM
    Write-Output -InputObject "Enrolling Azure subscription $azsubscriptionid"
    New-PimAzSubscriptionEnrolment -azsubscriptionid $azsubscriptionid
}
catch {
    Write-Error -Message $_
    break
}
try {
    #Check if onlyaddaadgroups is true or false to determine if this step is to be executed
    if ($onlyaddaadgroups -eq $false) {
        #Set baseline role settings for enrolled subscription based on role and baseline input
        Write-Output -InputObject "Setting role setting baseline for Azure subscription $azsubscriptionid"
        Set-PimAzSubscriptionRoleSetting -azsubscriptionid $azsubscriptionid -azroledefids $azroledefids -settingsprofile $settingsprofile
    }
    else {
        #Skip setting baseline role settings
        Write-Output -InputObject "Skipping role setting baseline for Azure subscription $azsubscriptionid"
    }
}
catch {
    Write-Error -Message $_
    break
}
try {
    #Add Azure AD Groups as eligible members to roles
    Write-Output -InputObject "Adding Azure AD groups to each role for Azure subscription $azsubscriptionid"
    New-PimAzRoleAssignment -azsubscription $azsubscriptionid -azroledefids $azroledefids -aadgroups $aadgroups -assignmenttype $assignmenttype
}
catch {
    Write-Error -Message $_
    break
}
try {
    #Execution completed
    Write-Output -InputObject "Job execution completed for Azure subscription $azsubscriptionid"
}
catch {
    Write-Error -Message $_
    break
}