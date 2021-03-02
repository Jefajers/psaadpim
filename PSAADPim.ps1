#start function section
function Get-PimTime {
    <#
    .SYNOPSIS
        Get current system time and provide it back as AADPim expect
    .EXAMPLE
        Get-PimTime
    .OUTPUTS
        yyyy/MM/ddTHH:mmZ
    #>
    try {
        $timenow = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        return $timenow
    }
    catch {
        Write-Error -Message $_
        break
    }
}
function Connect-PimAz {
    <#
    .SYNOPSIS
        Connect to required resources AzureAD and Azure
    .PARAMETER AzAutomationCredentialUserName
        The Azure Automation Credential user name to be used
    .PARAMETER AzAutomationCredentialSPNName
        The Azure Automation Credential spn name to be used
    .PARAMETER AzADTenant
        Azure AD Tenant ID: xxxx-xxxx-xxxx-xxxx
    .EXAMPLE
        Connect-PimAz -AzAutomationCredentialUserName <ReplaceWithNameofAzureAdUserCredential> -AzAutomationCredentialSPNName <ReplaceWithNameofSPNCredential> -IdentityType spn -AzADTenant xxxx-xxxx-xxxx-xxxx
    .OUTPUTS
        N/A
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string] $AzAutomationCredentialUserName,
        [Parameter(Mandatory = $true)]
        [string] $AzAutomationCredentialSPNName,
        [Parameter(Mandatory = $true)]
        [string] $AzADTenant
    )
    try {
        #Tenant
        $AzADTenant = Get-AutomationVariable -Name $AzADTenant
        #Gather service user account credential
        $AzureAdPimCredUser = Get-AutomationPSCredential -Name $AzAutomationCredentialUserName
        $AzureAdPimCredUserName = $AzureAdPimCredUser.Username
        #Gather service spn credential
        $AzureAdPimCredSPN = Get-AutomationPSCredential -Name $AzAutomationCredentialSPNName
        $AzureAdPimCredSPNName = $AzureAdPimCredSPN.Username
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Output -InputObject "Unable to gather service account credentials, $ErrorMessage"
        Write-Error -Message $_
        break
    }
    try {
        #Connect to AzureAD and get token
        $resource = "https://graph.microsoft.com/"
        $client_id = $AzureAdPimCredSPNName
        $client_secret = $($AzureAdPimCredSPN.GetNetworkCredential().Password)
        $authority = "https://login.microsoftonline.com/$AzADTenant"
        $tokenEndpointUri = "$authority/oauth2/token"
        $content = "grant_type=password&client_id=$client_id&client_secret=$client_secret&username=$AzureAdPimCredUserName&password=$($AzureAdPimCredUser.GetNetworkCredential().Password)&resource=$resource"
        $response = Invoke-RestMethod -Uri $tokenEndpointUri -Body $content -Method Post -UseBasicParsing
        $accesstoken = $response.access_token
       #Connect to the Graph
        Connect-MgGraph -AccessToken $accesstoken -TenantId $AzADTenant
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Output -InputObject "Unable to generate AAD token for SPN auth, $ErrorMessage"
        Write-Error -Message $_
        break
    }
    try {
        #Connect to Azure
        Connect-AzAccount -ServicePrincipal -Credential $AzureAdPimCredSPN -Tenant $AzADTenant
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Output -InputObject "Unable to connect to Azure, $ErrorMessage"
        Write-Error -Message $_
        break
    }
}
function Get-PimAzSubscriptionId {
    <#
    .SYNOPSIS
        Translates Azure subscription ID into Azure AD PIM resource ID
    .PARAMETER azsubscriptionid
        The Azure subscription id to be used as scope in the following format: xxxx-xxxx-xxxx-xxxx
    .EXAMPLE
        Get-PimAzSubscriptionId -azsubscriptionid xxxx-xxxx-xxxx-xxxx
    .OUTPUTS
        $_.value:
        Name                           Value
        ----                           -----
        originTenantId
        id                             xxxx-xxxx-xxxx-xxxx-xxxx
        displayName                    Displayname of subscription
        managedAt
        externalId                     /subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx
        registeredDateTime             xxxx
        status                         Current status will be displayed here
        onboardDateTime                xxxx
        type                           subscription
        registeredRoot
    #>
    param(
        [Parameter (Mandatory = $true)]
        [guid] $azsubscriptionid
    )
    try {
        #Check if Azure subscription exist
        Get-AzSubscription -SubscriptionId $azsubscriptionid | Out-Null
    }
    catch {
        Write-Error -Message $_
        break
    }
    try {
        #Get PIM resourceid of the az subscription
        $subidfilterstring = "ExternalId eq '/subscriptions/$azsubscriptionid'"
        #Call API
        $Uri = "https://graph.microsoft.com/beta/privilegedAccess/azureResources/resources?filter=$subidfilterstring"
        $pimazsubid = Invoke-GraphRequest -Uri $Uri -Method GET
        if ($pimazsubid -eq $null) {
            Write-Error -Message "Azure subscription $azsubscriptionid is not found in PIM"
            break
        }
        return $pimazsubid
    }
    catch {
        Write-Error -Message $_
        break
    }
}
function Get-PimAzRoledefinitionId {
    <#
    .SYNOPSIS
        Translates Azure RBAC Roledefinition ID into Azure AD PIM resource ID
    .PARAMETER azsubscriptionid
        The Azure subscription id in the following format: xxxx-xxxx-xxxx-xxxx
    .PARAMETER azroledefinitionid
        The Azure RBAC roledefinition id in the following format: xxxx-xxxx-xxxx-xxxx
    .EXAMPLE
        Get-PimAzRoledefinitionId -azsubscriptionid xxxx-xxxx-xxxx-xxxx -azroledefinitionid xxxx-xxxx-xxxx-xxxx
    .OUTPUTS
        $_.value:
        Name                           Value
        ----                           -----
        resourceId                     xxxx-xxxx-xxxx-xxxx
        type                           BuiltInRole or Custom
        externalId                     /subscriptions/xxxx-xxxx-xxxx-xxxx/providers/Microsoft.Authorization/roleDefinitions/xxxx-xxxx-xxxx-xxxx
        displayName                    Displayname of role
        id                             xxxx-xxxx-xxxx-xxxx
        templateId                     xxxx-xxxx-xxxx-xxxx
    #>
    param(
        [Parameter (Mandatory = $true)]
        [guid] $azsubscriptionid,
        [Parameter(Mandatory = $true)]
        [guid] $azroledefinitionid
    )
    try {
        #Get PIM resourceid of the az subscription
        $pimazsubid = Get-PimAzSubscriptionId -azsubscriptionid $azsubscriptionid
        #Get role information with API call
        $Uri = "https://graph.microsoft.com/beta/privilegedAccess/azureResources/resources/$($pimazsubid.value.id)/roleDefinitions?filter=templateId+eq+'$azroledefinitionid'"        
        $pimazroleid = Invoke-GraphRequest -Uri $Uri -Method GET
        return $pimazroleid
    }
    catch {
        Write-Error -Message $_
        break
    }
}
function Get-PimAzRoleSettingId {
    <#
    .SYNOPSIS
        Translates Azure subscription ID and Azure RBAC Roledefinition ID and into Azure AD PIM rolesetting resource ID
    .PARAMETER azsubscriptionid
        The Azure subscription id in the following format: xxxx-xxxx-xxxx-xxxx
    .PARAMETER azroledefinitionid
        The Azure RBAC roledefinition id in the following format: xxxx-xxxx-xxxx-xxxx
    .EXAMPLE
        Get-PimAzRoleSettingId -azsubscriptionid xxxx-xxxx-xxxx-xxxx -azroledefinitionid xxxx-xxxx-xxxx-xxxx
    .OUTPUTS
        $_.value:
        Name                           Value
        ----                           -----
        lastUpdatedDateTime
        roleDefinitionId               xxxx-xxxx-xxxx-xxxx
        id                             xxxx-xxxx-xxxx-xxxx
        adminMemberSettings            
        lastUpdatedBy
        resourceId                     xxxx-xxxx-xxxx-xxxx
        adminEligibleSettings          
        userMemberSettings             
        userEligibleSettings           
        isDefault                      True or False
    #>
    param(
        [Parameter (Mandatory = $true)]
        [guid] $azsubscriptionid,
        [Parameter(Mandatory = $true)]
        [guid] $azroledefinitionid
    )
    try {
        #Get PIM resourceid of the az subscription
        $pimazsubid = Get-PimAzSubscriptionId -azsubscriptionid $azsubscriptionid
        #Get PIM resourceid for the az roledefinitionid
        $pimazroleid = Get-PimAzRoledefinitionId -azsubscriptionid $azsubscriptionid -azroledefinitionid $azroledefinitionid
        #Construct rolesetting id filter
        $rolesettingidstring = "ResourceId eq '$($pimazsubid.value.id)' and RoleDefinitionId eq '$($pimazroleid.value.id)'"
        #Get role setting information with API call
        $Uri = "https://graph.microsoft.com/beta/privilegedAccess/azureResources/roleSettings?filter=$rolesettingidstring"
        $pimazrolesettingid = Invoke-GraphRequest -Uri $Uri -Method GET
        return $pimazrolesettingid
    }
    catch {
        Write-Error -Message $_
        break
    }
}
function Get-PimAzSubscriptionEnrolment {
    <#
    .SYNOPSIS
        Checks if the subscription is enroled
    .PARAMETER azsubscriptionid
        The Azure subscription id to be used as scope in the following format: xxxx-xxxx-xxxx-xxxx
    .EXAMPLE
        Get-PimAzSubscriptionEnrolment -azsubscriptionid xxxx-xxxx-xxxx-xxxx
    .OUTPUTS
    #>
    param(
        [Parameter (Mandatory = $true)]
        [guid] $azsubscriptionid
    )
    try {
        #Check if Azure subscription exist
        Get-AzSubscription -SubscriptionId $azsubscriptionid | Out-Null
    }
    catch {
        Write-Error -Message $_
        break
    }
    try {
        #Check if Azure subscription is already enroled
        $subenrollmentcheck = Get-AzRoleAssignment -Scope /subscriptions/$azsubscriptionid | Where-Object { $_.DisplayName -eq 'MS-PIM' }        
        return $subenrollmentcheck
    }
    catch {
        Write-Error -Message $_
        break
    }
}
function Register-PimAzSubscription {
    <#
    .SYNOPSIS
        Performs important API call to ensure PIM resource discovery in Portal
    .PARAMETER azsubscriptionid
        The Azure subscription id to be used as scope in the following format: xxxx-xxxx-xxxx-xxxx
    .EXAMPLE
        Register-PimAzSubscription -azsubscriptionid xxxx-xxxx-xxxx-xxxx
    .OUTPUTS
    #>
    param (
        [Parameter(Mandatory = $true)]
        [guid]$azsubscriptionid
    )
    try {
        #Construct API call body
        $Body = @{    
            "externalId" = "/subscriptions/$azsubscriptionid"
        }
        #Call API to register subscription
        $Uri = "https://graph.microsoft.com/beta/privilegedAccess/azureResources/resources/register"
        Invoke-GraphRequest -Uri $uri -Method POST -Body ($Body | ConvertTo-Json)
    }
    catch {
        if ($_ -like "*The Role assignment already exists*") {
            Write-Output -InputObject "MS-PIM role assignment already exists"
        } else {
            Write-Error -Message $_
            break
        }
    }
}
function New-PimAzSubscriptionEnrolment {
    <#
    .SYNOPSIS
        Enrols designated Azure subscription into Azure AD PIM management
    .PARAMETER azsubscriptionid
        The Azure subscription id in the following format: xxxx-xxxx-xxxx-xxxx
    .EXAMPLE
        New-PimAzSubscriptionEnrollment -azsubscription xxxx-xxxx-xxxx-xxxx
    .OUTPUTS
        N/A
    #>
    param(
        [Parameter (Mandatory = $true)]
        [guid] $azsubscriptionid
    )
    try {
        #Check if Azure subscription exist
        Get-AzSubscription -SubscriptionId $azsubscriptionid
    }
    catch {
        Write-Error -Message $_
        break
    }
    try {
        #Check if Azure subscription is already enroled
        Write-Output -InputObject "Checking enrolment status of Azure subscription $azsubscriptionid"
        $subenrollmentcheck = Get-PimAzSubscriptionEnrolment $azsubscriptionid
    }
    catch {
        Write-Error -Message $_
        break
    }
    #No try catch in this section to avoid false positive with underlying module
    if ($subenrollmentcheck) {
        Write-Output -InputObject "Azure subscription $azsubscriptionid is already enroled in Azure AD PIM"
    }
    else {
        #Enroll subscription to Azure AD PIM
        Write-Output -InputObject "Enroling Azure subscription $azsubscriptionid into Azure AD PIM"
        Register-PimAzSubscription -azsubscriptionid $azsubscriptionid
        Start-Sleep -Seconds 10
        try {
            #Check if Azure subscription is now enroled
            $subenrollmentcheck = Get-PimAzSubscriptionEnrolment $azsubscriptionid
            if ($subenrollmentcheck) {
                Write-Output -InputObject "Azure subscription $azsubscriptionid is now enroled in Azure AD PIM"
            } else {
                Write-Output -InputObject "Azure subscription $azsubscriptionid is not enroled in Azure AD PIM, please investigate"
                break
            }
        }
        catch {
            Write-Error -Message $_
            break
        }
    }
}
function Set-PimAzSubscriptionRoleSetting {
    <#
    .SYNOPSIS
        Configures Azure role with Azure AD PIM baseline settings
    .PARAMETER azsubscription
        The Azure subscription id in the following format: xxxx-xxxx-xxxx-xxxx
    .PARAMETER azazadroleids
        The Azure role definition id that PIM should baseline in the following format (json array):[{"Id":"xxxx-xxxx-xxxx-xxxx"},{"Id":"xxxx-xxxx-xxxx-xxxx"}]
        Can be collected by running Get-AzRoleDefinition and look for the ID matching the role that matches desired scope
    .PARAMETER settingsprofile
    This defines which set of settings to apply cross all three avaialbe dimeions of a role
    .EXAMPLE
        Set-PimAzSubscriptionRoleSetting -azsubscription xxxx-xxxx-xxxx-xxxx -azroledefids xxxx-xxxx-xxxx-xxxx -settingsprofile $settingsprofile
    .OUTPUTS
        N/A
    #>
    param(
        [Parameter (Mandatory = $true)]
        [guid] $azsubscriptionid,
        [Parameter(Mandatory = $true)]
        [array] $azroledefids,
        [Parameter(Mandatory = $true)]
        $settingsprofile
    )
    try {
        #Get PIM resourceid of the az subscription
        $pimazsubid = Get-PimAzSubscriptionId -azsubscriptionid $azsubscriptionid
    }
    catch {
        Write-Output -InputObject "Unable to get azsubscription $azsubscriptionid, $ErrorMessage"
        Write-Error -Message $_
        break
    }
    #Loop each role id
    foreach ($roleid in $azroledefids) {
        try {
            #Get PIM resourceid for the az roledefinitionid
            Write-Output -InputObject "Processing Azure roleid: $($roleid.id)"
            $pimazroleid = Get-PimAzRoledefinitionId -azsubscriptionid $azsubscriptionid -azroledefinitionid $roleid.Id
        }
        catch {
            Write-Output -InputObject "Unable to get azsroledefinitionid $roleid, $ErrorMessage"
            Write-Error -Message $_
            break
        }
        try {
            #Get PIM resourceid for the az rolesettingid
            $pimazrolesettingid = Get-PimAzRoleSettingId -azsubscriptionid $azsubscriptionid -azroledefinitionid $roleid.Id
        }
        catch {
            Write-Output -InputObject "Unable to get azsroledsettingid for the following roleid $roleid, $ErrorMessage"
            Write-Error -Message $_
            break
        }
        #Loop each desired role setting from baseline input
        foreach ($setting in $settingsprofile) {
            Write-Output -InputObject "Processing settings..."
                $Body = $setting
                try {
                    #Set Role settings
                    $Uri = "https://graph.microsoft.com/beta/privilegedAccess/azureResources/roleSettings/$($pimazrolesettingid.value.id)"
                    Invoke-GraphRequest -Uri $uri -Method PATCH -Body ($Body | ConvertTo-Json -Depth 100)
                }
                catch {
                    Write-Output -InputObject "Unable to set $setting in rolesetting $($pimazrolesettingid.value.id), $ErrorMessage"
                    Write-Error -Message $_
                    break
                }
        }

    }
}
function New-PimAzRoleAssignment {
    <#
    .SYNOPSIS
        Creates Azure roleassignment in Azure AD PIM based on Azure AD group Id's
    .PARAMETER azsubscription
        The Azure subscription id in the following format: xxxx-xxxx-xxxx-xxxx
    .PARAMETER azazadroleids
        The Azure role definition id that PIM should baseline in the following format (json array):[{"Id":"xxxx-xxxx-xxxx-xxxx"},{"Id":"xxxx-xxxx-xxxx-xxxx"}]
        Can be collected by running Get-AzRoleDefinition and look for the ID matching the role that matches desired scope
    .PARAMETER aadgroups
        The Azure AD group object id in the following format (json array):[{"ObjectId":"xxxx-xxxx-xxxx-xxxx"},{"ObjectId":"xxxx-xxxx-xxxx-xxxx"}]
        Can be collected by running Get-AzureADGroup and look for the ID matching the group that matches desired scope
    .PARAMETER assignmenttype
        The assignmenttype indicates if the group should be added as Eligible or Active (this parameter is case sensitive)
    .EXAMPLE
        New-PimAzRoleAssignment -azsubscription xxxx-xxxx-xxxx-xxxx -azroledefids [{"Id":"xxxx-xxxx-xxxx-xxxx"}] -aadgroups [{"ObjectId":"xxxx-xxxx-xxxx-xxxx"}] -assignmenttype Eligible
    .OUTPUTS
        N/A
    #>
    param(
        [Parameter (Mandatory = $true)]
        [guid] $azsubscriptionid,
        [Parameter(Mandatory = $true)]
        [array] $azroledefids,
        [Parameter(Mandatory = $true)]
        [array] $aadgroups,
        [Parameter(Mandatory = $true)]
        [ValidateSet("Eligible", "Active", IgnoreCase = $false)]
        [string] $assignmenttype
    )
    try {
        #Get PIM resourceid of the az subscription
        $pimazsubid = Get-PimAzSubscriptionId -azsubscriptionid $azsubscriptionid
    }
    catch {
        Write-Output -InputObject "Unable to get azsubscription $azsubscriptionid, $ErrorMessage"
        Write-Error -Message $_
        break
    }
    #Loop each role id
    foreach ($roleid in $azroledefids) {
        try {
            #Get PIM resourceid for the az roledefinitionid
            $pimazroleid = Get-PimAzRoledefinitionId -azsubscriptionid $azsubscriptionid -azroledefinitionid $roleid.Id
        }
        catch {
            Write-Output -InputObject "Unable to get azsroledefinitionid $roleid, $ErrorMessage"
            Write-Error -Message $_
            break
        }
        #Loop each desired role setting from baseline input
        foreach ($aadgroup in $aadgroups) {
            Write-Output -InputObject "Processing to add Azure AD Group: $($aadgroup.ObjectId) to role: $($roleid.Id) with assignmenttype: $assignmenttype"
            try {
                #Validate Azure AD group id
                $group = Get-MgGroup -GroupId $aadgroup.ObjectId
            }
            catch {
                Write-Error -Message $_
                break
            }
            try {
                if ($assignmenttype -eq "Eligible") {
                    #Check if group already added
                    $groupstatefilterstring = "ResourceId eq '$($pimazsubid.value.id)' and RoleDefinitionId eq '$($pimazroleid.value.id)' and SubjectId eq '$($group.Id)'"
                    $Uri = "https://graph.microsoft.com/beta/privilegedAccess/azureResources/roleAssignments?filter=$groupstatefilterstring"
                    $groupstatecheck = Invoke-GraphRequest -Uri $uri -Method GET
                    if ($groupstatecheck.value.assignmentstate -eq "Eligible") {
                        Write-Output -InputObject "This group: $($group.Id) with this role: $($roleid.Id) already seem to have an $assignmenttype assignment, skipping add operation. Please check this group assignment manually"
                    }
                    else {
                        #Generate schedule object
                        $timenow = Get-PimTime
                        $scheduleType = "Once"
                        #Justification for assignment
                        $justification = "AzureADPim enrollment service taking automated action to add aadgroup:$($group.Id) in $assignmenttype state on azure role:$($roleid.Id)"
                        #Create role assignment configuration
                        $Body = @(
                            [pscustomobject]@{
                                "roleDefinitionId" = "$($pimazroleid.value.id)";
                                "resourceId" = "$($pimazsubid.value.id)";
                                "subjectId" = "$($group.Id)";
                                "assignmentState" = "$assignmenttype";
                                "type" = "AdminAdd";
                                "reason" = "$justification";
                                "schedule" = @{ "startDateTime" = "$timenow"; "type" = "$scheduleType" }
                            }
                        )
                        $Uri = "https://graph.microsoft.com/beta/privilegedAccess/azureResources/roleAssignmentRequests"
                        Invoke-GraphRequest -Uri $uri -Method POST -Body ($Body | ConvertTo-Json -Depth 100)
                    }
                }
                if ($assignmenttype -eq "Active") {
                    #Check if group already added
                    $groupstatefilterstring = "ResourceId eq '$($pimazsubid.value.id)' and RoleDefinitionId eq '$($pimazroleid.value.id)' and SubjectId eq '$($group.Id)'"
                    $Uri = "https://graph.microsoft.com/beta/privilegedAccess/azureResources/roleAssignments?filter=$groupstatefilterstring"
                    $groupstatecheck = Invoke-GraphRequest -Uri $uri -Method GET
                    if ($groupstatecheck.value.assignmentstate -eq "Active") {
                        Write-Output -InputObject "This group: $($group.Id) with this role: $($roleid.Id) already seem to have an $assignmenttype assignment, skipping add operation. Please check this group assignment manually"
                    }
                    else {
                        #Generate schedule object
                        $timenow = Get-PimTime
                        $scheduleType = "Once"
                        #Justification for assignment
                        $justification = "AzureADPim enrollment service taking automated action to add aadgroup:$($group.Id) in $assignmenttype state on azure role:$($roleid.Id)"
                        #Create role assignment configuration
                        $Body = @(
                            [pscustomobject]@{
                                "roleDefinitionId" = "$($pimazroleid.value.id)";
                                "resourceId" = "$($pimazsubid.value.id)";
                                "subjectId" = "$($group.Id)";
                                "assignmentState" = "$assignmenttype";
                                "type" = "AdminAdd";
                                "reason" = "$justification";
                                "schedule" = @{ "startDateTime" = "$timenow"; "type" = "$scheduleType" }
                            }
                        )
                        $Uri = "https://graph.microsoft.com/beta/privilegedAccess/azureResources/roleAssignmentRequests"
                        Invoke-GraphRequest -Uri $uri -Method POST -Body ($Body | ConvertTo-Json -Depth 100)
                    }
                }
            }
            catch {
                Write-Output -InputObject "Unable to create role assignment for role $($pimazroleid.Id) and AAD group $($group.Id) in Azure subscription $($pimazsubid.Id), $ErrorMessage"
                Write-Error -Message $_
                break
            }
        }
    }
}
#end function section