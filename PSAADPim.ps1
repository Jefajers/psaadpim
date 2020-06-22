#region function section
function Get-PimTime {
    <#
    .SYNOPSIS
        Gets current system time and provides it back as Pim expect
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
    .PARAMETER AzAutomationCredentialName
        The Azure Automation Credential name to be used
    .PARAMETER IdentityType
        Set service account type to be used by the function, either spn or user in the following format: [spn]/[user]
    .PARAMETER AzADTenant
        Set service account type to be used by the function, either spn or user in the following format: [spn]/[user]
    .EXAMPLE
        Connect-PimAz -AzAutomationCredentialName nameofcredential -IdentityType spn -AzADTenant xxxx-xxxx-xxxx-xxxx
    .OUTPUTS
        N/A
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string] $AzAutomationCredentialName,
        [Parameter(Mandatory = $true)]
        [string] $IdentityType,
        [Parameter(Mandatory = $true)]
        [string] $AzADTenant
    )
    try {
        #Gather service account credential
        $AzureAdPimCred = Get-AutomationPSCredential -Name $AzAutomationCredentialName -ErrorAction Stop
        $AzureAdPimCredUserName = $AzureAdPimCred.Username
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Output -InputObject "Unable to gather service account credential, $ErrorMessage"
        Write-Error -Message $_
        break
    }
    try {
        #Get Azure AD token with graph
        if ($IdentityType -eq 'spn') {
            $Token = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$AzADTenant/oauth2/v2.0/token" `
                -UseBasicParsing -ContentType "application/x-www-form-urlencoded" `
                -Body "client_id=$AzureAdPimCredUserName&scope=https%3A%2F%2Fgraph.windows.net%2F.default&client_secret=$($AzureAdPimCred.GetNetworkCredential().Password)&grant_type=client_credentials"
        }
        else {

        }
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Output -InputObject "Unable to generate AAD token for SPN auth, $ErrorMessage"
        Write-Error -Message $_
        break
    }

    try {
        #Connect to Azure AD
        if ($IdentityType -eq 'spn') {
            Connect-AzureAD -TenantId $AzADTenant -AadAccessToken $Token.access_token -AccountId 'SPNConnection'
        }
        else {
            Connect-AzureAD -TenantId $AzADTenant -Credential $AzureAdPimCred -ErrorAction Stop
        }
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        Write-Output -InputObject "Unable to connect to Azure AD, $ErrorMessage"
        Write-Error -Message $_
        break
    }

    try {
        #Connect to Azure
        if ($IdentityType -eq 'spn') {
            Connect-AzAccount -ServicePrincipal -Credential $AzureAdPimCred -Tenant $AzADTenant -ErrorAction Stop
        }
        else {
            Connect-AzAccount -Tenant $AzADTenant -Credential $AzureAdPimCred -ErrorAction Stop
        }
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
        Id                  : xxxx-xxxx-xxxx-xxxx-xxxx
        ExternalId          : /subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx
        Type                : subscription
        DisplayName         : Displayname of subscription
        Status              : Current status will be displayed here
    #>
    param(
        [Parameter (Mandatory = $true)]
        [ValidateScript( {
                try {
                    [System.Guid]::Parse($_) | Out-Null
                    $true
                }
                catch {
                    $false
                }
            })]
        [string] $azsubscriptionid
    )
    try {
        #Check if Azure subscription exist
        Get-AzSubscription -SubscriptionId $azsubscriptionid -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Error -Message $_
        break
    }
    try {
        #Get PIM resourceid of the az subscription
        $subidfilterstring = "ExternalId" + " " + "eq" + " " + "'" + "/subscriptions/" + "$azsubscriptionid" + "'"
        $pimazsubid = Get-AzureADMSPrivilegedResource -ProviderId AzureResources -Filter $subidfilterstring | Select-Object Id, ExternalId, Type, DisplayName, Status
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
        Id                      : xxxx-xxxx-xxxx-xxxx
        ResourceId              : xxxx-xxxx-xxxx-xxxx
        ExternalId              : /subscriptions/xxxx-xxxx-xxxx-xxxx/providers/Microsoft.Authorization/roleDefinitions/xxxx-xxxx-xxxx-xxxx
        DisplayName             : NameOfRole
    #>
    param(
        [Parameter (Mandatory = $true)]
        [ValidateScript( {
                try {
                    [System.Guid]::Parse($_) | Out-Null
                    $true
                }
                catch {
                    $false
                }
            })]
        [string] $azsubscriptionid,
        [Parameter(Mandatory = $true)]
        [string] $azroledefinitionid
    )
    try {
        #Get PIM resourceid of the az subscription
        $pimazsubid = Get-PimAzSubscriptionId -azsubscriptionid $azsubscriptionid
        #Construct role id filter
        $roleidfilterstring = "ExternalId" + " " + "eq" + " " + "'" + "/subscriptions/" + "$azsubscriptionid" + "/providers/Microsoft.Authorization/roleDefinitions/" + "$azroledefinitionid" + "'"
        #Get role information
        $pimazroleid = Get-AzureADMSPrivilegedRoleDefinition -ProviderId AzureResources -ResourceId $pimazsubid.Id  -Filter $roleidfilterstring | Select-Object Id, ResourceId, ExternalId, DisplayName
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
        Id                    : xxxx-xxxx-xxxx-xxxx
        ResourceId            : xxxx-xxxx-xxxx-xxxx
        RoleDefinitionId      : xxxx-xxxx-xxxx-xxxx
        IsDefault             :
        LastUpdatedDateTime   :
        LastUpdatedBy         :
        AdminEligibleSettings :
        AdminMemberSettings   :
        UserEligibleSettings  :
        UserMemberSettings    :
    #>
    param(
        [Parameter (Mandatory = $true)]
        [ValidateScript( {
                try {
                    [System.Guid]::Parse($_) | Out-Null
                    $true
                }
                catch {
                    $false
                }
            })]
        [string] $azsubscriptionid,
        [Parameter(Mandatory = $true)]
        [string] $azroledefinitionid
    )
    try {
        #Get PIM resourceid of the az subscription
        $pimazsubid = Get-PimAzSubscriptionId -azsubscriptionid $azsubscriptionid
        #Get PIM resourceid for the az roledefinitionid
        $pimazroleid = Get-PimAzRoledefinitionId -azsubscriptionid $azsubscriptionid -azroledefinitionid $azroledefinitionid
        #Construct rolesetting id filter
        $rolesettingidstring = "ResourceId eq " + "'" + "$($pimazsubid.id)" + "'" + " and RoleDefinitionId eq " + "'" + "$($pimazroleid.id)" + "'"
        #Get role setting information
        $pimazrolesettingid = Get-AzureADMSPrivilegedRoleSetting -ProviderId AzureResources -Filter $rolesettingidstring
        return $pimazrolesettingid
    }
    catch {
        Write-Error -Message $_
        break
    }
}
function New-PimAzSubscriptionEnrollment {
    <#
    .SYNOPSIS
        Enrolls designated Azure subscription into Azure AD PIM management
    .PARAMETER azsubscriptionid
        The Azure subscription id in the following format: xxxx-xxxx-xxxx-xxxx
    .EXAMPLE
        New-PimAzSubscriptionEnrollment -azsubscription xxxx-xxxx-xxxx-xxxx
    .OUTPUTS
        N/A
    #>
    param(
        [Parameter (Mandatory = $true)]
        [ValidateScript( {
                try {
                    [System.Guid]::Parse($_) | Out-Null
                    $true
                }
                catch {
                    $false
                }
            })]
        [string] $azsubscriptionid
    )
    try {
        #Check if Azure subscription exist
        Get-AzSubscription -SubscriptionId $azsubscriptionid -ErrorAction Stop
    }
    catch {
        Write-Error -Message $_
        break
    }
    try {
        #Check if Azure subscription is already enrolled
        $subenrollmentcheck = Get-PimAzSubscriptionId -azsubscriptionid $azsubscriptionid
    }
    catch {
        Write-Error -Message $_
        break
    }
    try {
        if ($subenrollmentcheck) {
            Write-Output -InputObject "Azure subscription $azsubscriptionid is already enrolled in Azure AD PIM"
        }
        else {
            #Enroll subscription to Azure AD PIM
            Write-Output -InputObject "Enrolling Azure subscription $azsubscriptionid into Azure AD PIM"
            $subExternalId = "/subscriptions/" + "$azsubscriptionid"
            Add-AzureADMSPrivilegedResource -ProviderId AzureResources -ExternalId $subExternalId
        }
    }
    catch {
        Write-Output -InputObject "Unable to enable PIM on $azsubscriptionid, $ErrorMessage"
        Write-Error -Message $_
        break
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
        [ValidateScript( {
                try {
                    [System.Guid]::Parse($_) | Out-Null
                    $true
                }
                catch {
                    $false
                }
            })]
        [string] $azsubscriptionid,
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
            Write-Output -InputObject "Processing setting $($setting.dimension), $($setting.name), $($setting.value)"
            if ($setting.dimension -eq "AdminEligibleSettings") {

                #Generate setting object
                $settingobject = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedRuleSetting
                #Populate setting object based on input
                $settingobject.RuleIdentifier = "$($setting.name)"
                $settingobject.Setting = "$($setting.value)"
                try {
                    #Set Role settings
                    Set-AzureADMSPrivilegedRoleSetting -ProviderId AzureResources -Id $pimazrolesettingid.Id -ResourceId $pimazsubid.Id -RoleDefinitionId $pimazroleid.Id -AdminEligibleSettings $settingobject
                }
                catch {
                    Write-Output -InputObject "Unable to set $setting in rolesetting $($pimazrolesettingid.Id), $ErrorMessage"
                    Write-Error -Message $_
                    break
                }

            }

            if ($setting.dimension -eq "AdminMemberSettings") {

                #Generate setting object
                $settingobject = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedRuleSetting
                #Populate setting object based on input
                $settingobject.RuleIdentifier = "$($setting.name)"
                $settingobject.Setting = "$($setting.value)"
                try {
                    #Set Role settings
                    Set-AzureADMSPrivilegedRoleSetting -ProviderId AzureResources -Id $pimazrolesettingid.Id -ResourceId $pimazsubid.Id -RoleDefinitionId $pimazroleid.Id -AdminMemberSettings $settingobject
                }
                catch {
                    Write-Output -InputObject "Unable to set $setting in rolesetting $($pimazrolesettingid.Id), $ErrorMessage"
                    Write-Error -Message $_
                    break
                }

            }

            if ($setting.dimension -eq "UserMemberSettings") {

                #Generate setting object
                $settingobject = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedRuleSetting
                #Populate setting object based on input
                $settingobject.RuleIdentifier = "$($setting.name)"
                $settingobject.Setting = "$($setting.value)"
                try {
                    #Set Role settings
                    Set-AzureADMSPrivilegedRoleSetting -ProviderId AzureResources -Id $pimazrolesettingid.Id -ResourceId $pimazsubid.Id -RoleDefinitionId $pimazroleid.Id -UserMemberSettings $settingobject
                }
                catch {
                    Write-Output -InputObject "Unable to set $setting in rolesetting $($pimazrolesettingid.Id), $ErrorMessage"
                    Write-Error -Message $_
                    break
                }

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
        [ValidateScript( {
                try {
                    [System.Guid]::Parse($_) | Out-Null
                    $true
                }
                catch {
                    $false
                }
            })]
        [string] $azsubscriptionid,
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
                $group = Get-AzureADGroup -ObjectId $aadgroup.ObjectId
            }
            catch {
                Write-Error -Message $_
                break
            }
            try {
                if ($assignmenttype -eq "Eligible") {
                    #Check if group already added
                    $groupstatefilterstring = "RoleDefinitionId" + " " + "eq" + " " + "'" + "$($pimazroleid.Id)" + "'" + " " + "and" + " " + "SubjectId" + " " + "eq" + " " + "'" + "$($group.ObjectId)" + "'"
                    $groupstatecheck = Get-AzureADMSPrivilegedRoleAssignment -ProviderId AzureResources -ResourceId $pimazsubid.Id -Filter $groupstatefilterstring
                    if ($groupstatecheck.AssignmentState -eq "Eligible") {
                        Write-Output -InputObject "This group: $($group.ObjectId) with this role: $($roleid.Id) already seem to have an $assignmenttype assignment, skipping add operation. Please check this group assignment manually"
                    }
                    else {
                        #Generate schedule object
                        $schedule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedSchedule
                        #Populate schedule object with current time
                        $schedule.Type = "Once"
                        $timenow = Get-PimTime
                        $schedule.StartDateTime = $timenow
                        #Justification for assignment
                        $justification = "AzureADPim enrollment service taking automated action to add aadgroup:$($group.ObjectId) in $assignmenttype state on azure role:$($roleid.Id)"
                        #Create role assignment configuration
                        Open-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId AzureResources -Schedule $schedule -ResourceId $pimazsubid.Id -RoleDefinitionId $pimazroleid.Id -SubjectId $group.ObjectId -AssignmentState $assignmenttype -Type "AdminAdd" -Reason $justification
                    }

                }
                if ($assignmenttype -eq "Active") {
                    #Check if group already added
                    $groupstatefilterstring = "RoleDefinitionId" + " " + "eq" + " " + "'" + "$($pimazroleid.Id)" + "'" + " " + "and" + " " + "SubjectId" + " " + "eq" + " " + "'" + "$($group.ObjectId)" + "'"
                    $groupstatecheck = Get-AzureADMSPrivilegedRoleAssignment -ProviderId AzureResources -ResourceId $pimazsubid.Id -Filter $groupstatefilterstring
                    if ($groupstatecheck.AssignmentState -eq "Active") {
                        Write-Output -InputObject "This group: $($group.ObjectId) with this role: $($roleid.Id) already seem to have an $assignmenttype assignment, skipping add operation. Please check this group assignment manually"
                    }
                    else {
                        #Generate schedule object
                        $schedule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedSchedule
                        #Populate schedule object with current time
                        $schedule.Type = "Once"
                        $timenow = Get-PimTime
                        $schedule.StartDateTime = $timenow
                        #Justification for assignment
                        $justification = "AzureADPim enrollment service taking automated action to add aadgroup:$($group.ObjectId) in $assignmenttype state on azure role:$($roleid.Id)"
                        #Create role assignment configuration
                        Open-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId AzureResources -Schedule $schedule -ResourceId $pimazsubid.Id -RoleDefinitionId $pimazroleid.Id -SubjectId $group.ObjectId -AssignmentState $assignmenttype -Type "AdminAdd" -Reason $justification
                    }

                }
            }
            catch {
                Write-Output -InputObject "Unable to create role assignment for role $($pimazroleid.Id) and AAD group $($group.ObjectId) in Azure subscription $($pimazsubid.Id), $ErrorMessage"
                Write-Error -Message $_
                break
            }
        }
    }
}
#endregion function section