[comment]: # "Auto-generated SOAR connector documentation"
# Windows Defender ATP

Publisher: Splunk  
Connector Version: 3\.8\.0  
Product Vendor: Microsoft  
Product Name: Windows Defender ATP  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.5  

This app integrates with Windows Defender Advanced Threat Protection\(ATP\) to execute various containment, corrective, generic, and investigative actions

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2019-2022 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Defender ATP Instance Minimum Version Compatibility

-   With this major version 2.0.0 of the Windows Defender ATP app on Splunk SOAR, we declare support
    for (on and above) the cloud 'November-December 2019' GA release for the ATP instances. This app
    has been tested and certified on the mentioned GA release of the Defender ATP and its APIs.

## Playbook Backward Compatibility

-   The existing action parameters have been modified in the actions given below. Hence, it is
    requested to the end-user to please update their existing playbooks by re-inserting \| modifying
    \| deleting the corresponding action blocks, or by providing appropriate values to these action
    parameters to ensure the correct functioning of the playbooks created on the earlier versions of
    the app.

      

    -   List Devices - The 'IP' option has been removed from the value list of the \[input_type\]
        action parameter in the app version 3.0.0 because there is no specific API currently
        available to support the filtering of devices based on the IP in the Defender ATP.
    -   List Devices - The new \[query\] parameter has been added to support the additional OData V4
        filters.

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Defender ATP server. Below are the
default ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |

## Pagination Not Supported

-   Based on the base URL link ( [Microsoft Defender ATP API
    Documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/exposed-apis-list)
    ), the pagination is not supported by the Defender ATP APIs. Hence, this app does not implement
    the pagination for the below-mentioned actions.

      

    -   List Devices
    -   List Alerts
    -   List Sessions
    -   List Indicators
    -   Get Installed Software
    -   Get Discovered Vulnerabilities
    -   Get File Devices
    -   Get User Devices
    -   Get Domain Devices
    -   Get Missing KBs
    -   Run Query

## Explanation of Asset Configuration Parameters

-   Tenant ID - It is the Directory ID of the Microsoft Azure Active Directory on the Microsoft
    Azure portal.
-   Client ID - It is the Application ID of an application configured in the Microsoft Azure Active
    Directory.
-   Client Secret - It is the secret string used by the application to prove its identity when
    requesting a token. It can be generated for the configured application on the Microsoft Azure
    Active Directory.
-   Environment - Cloud services are provided by Azure and used to connect with Public, Government
    Community Cloud (GCC) or GCC High Azure cloud services.
-   Non Interactive Auth - It is used to determine the authentication method. If it is checked then
    non interactive auth will be used otherwise interactive auth will be used. Whenever this
    checkbox is toggled then the test connectivity action must be run again.

## Configure and set up permissions of the app created on the Microsoft Azure portal

<div style="margin-left: 2em">

#### Create the app

1.  Navigate to <https://portal.azure.com> .
2.  Log in with a user that has permission to create an app in the Azure Active Directory (AAD).
3.  Select the 'Azure Active Directory'.
4.  Select the 'App registrations' menu from the left-side panel.
5.  Select the 'New Registration' option at the top of the page.
6.  In the registration form, choose a name for your application and then click 'Register'.

#### Add permissions

7.  Select the 'API Permissions' menu from the left-side panel.
8.  Click on 'Add a permission'.
9.  Under the 'Select an API' section, select 'APIs my organization uses'.
10. Search for 'WindowsDefenderATP' keyword in the search box and click on the displayed option for
    it.
11. Provide the following Delegated and Application permissions to the app.
    -   **Application Permissions**

          

        -   AdvancedQuery.Read.All
        -   Alert.ReadWrite.All
        -   File.Read.All
        -   Ip.Read.All
        -   Machine.Isolate
        -   Machine.LiveResponse
        -   Machine.Offboard
        -   Machine.Read.All
        -   Machine.ReadWrite.All
        -   Machine.RestrictExecution
        -   Machine.Scan
        -   Machine.StopAndQuarantine
        -   Score.Read.All
        -   Software.Read.All
        -   Ti.ReadWrite.All
        -   Url.Read.All
        -   User.Read.All
        -   Vulnerability.Read.All

    -   **Delegated Permissions**

          

        -   AdvancedQuery.Read
        -   Alert.ReadWrite
        -   File.Read.All
        -   Ip.Read.All
        -   Machine.Isolate
        -   Machine.LiveResponse
        -   Machine.Offboard
        -   Machine.Read
        -   Machine.ReadWrite
        -   Machine.RestrictExecution
        -   Machine.Scan
        -   Machine.StopAndQuarantine
        -   Score.Read
        -   Software.Read
        -   Ti.ReadWrite
        -   Url.Read.All
        -   User.Read.All
        -   Vulnerability.Read
12. 'Grant Admin Consent' for it.
13. Again click on 'Add a permission'.
14. Under the 'Select an API' section, select 'Microsoft APIs'.
15. Click on the 'Microsoft Graph' option.
16. Provide the following Delegated permission to the app.
    -   **Delegated Permission**

          

        -   offline_access

#### Create a client secret

17. Select the 'Certificates & secrets' menu from the left-side panel.
18. Select 'New client secret' button to open a pop-up window.
19. Provide the description, select an appropriate option for deciding the client secret expiration
    time, and click on the 'Add' button.
20. Click 'Copy to clipboard' to copy the generated secret value and paste it in a safe place. You
    will need it to configure the asset and will not be able to retrieve it later.

#### Copy your application id and tenant id

21. Select the 'Overview' menu from the left-side panel.
22. Copy the **Application (client) ID** and **Directory (tenant) ID** . You will need these to
    configure the SOAR asset.

</div>

## Configure the Windows Defender ATP SOAR app's asset

When creating an asset for the app,

-   Check the checkbox if you want to use Non Interactive authentication mechanism otherwise
    Interactive auth mechanism will be used.

-   Provide the client ID of the app created during the previous step of app creation in the 'Client
    ID' field.

-   Provide the client secret of the app created during the previous step of app creation in the
    'Client Secret' field.

-   Provide the tenant ID of the app created during the previous step of Azure app creation in the
    'Tenant ID' field. For getting the value of tenant ID, navigate to the 'Azure Active Directory'
    on the Microsoft Azure portal; click on the 'App registrations' menu from the left-side panel;
    click on the earlier created app. The value displayed in the 'Directory (tenant) ID' is the
    required tenant ID.

-   Save the asset with the above values.

-   After saving the asset, a new uneditable field will appear in the 'Asset Settings' tab of the
    configured asset for the ATP app on SOAR. Copy the URL mentioned in the 'POST incoming for
    Windows Defender ATP to this location' field. Add a suffix '/result' to the URL copied in the
    previous step. The resulting URL looks like the one mentioned below.

      

                    https://<soar_host>/rest/handler/windowsdefenderatp_<appid>/<asset_name>/result
                  

-   Add the URL created in the earlier step into the 'Redirect URIs' section of the 'Authentication'
    menu for the registered app that was created in the previous steps on the Microsoft Azure
    portal. For the 'Redirect URIs' section, follow the below steps.

      

    1.  Below steps are required only in case of Interactive auth (i.e. If checkbox is unchecked)
    2.  Navigate to the 'Azure Active Directory' on the Microsoft Azure portal.
    3.  Click on the 'App registrations' menu from the left-side panel.
    4.  Click on the earlier created app. You can search for the app by name or client ID.
    5.  Navigate to the 'Authentication' menu of the app on the left-side panel.
    6.  Click on the 'Add a platform' button and select 'Web' from the displayed options.
    7.  Enter the URL created in the earlier section in the 'Redirect URIs' text-box.
    8.  Select the 'ID tokens' checkbox and click 'Save'.
    9.  This will display the 'Redirect URIs' under the 'Web' section displayed on the page.

## Interactive Method to run Test Connectivity

-   After setting up the asset and user, click the 'TEST CONNECTIVITY' button. A pop-up window will
    be displayed with appropriate test connectivity logs. It will also display a specific URL on
    that pop-up window.
-   Open this URL in a separate browser tab. This new tab will redirect to the Microsoft login page
    to complete the login process to grant the permissions to the app.
-   Log in using the same Microsoft account that was used to configure the Windows Defender ATP
    workflow and the application on the Microsoft Azure Portal. After logging in, review the
    requested permissions listed and click on the 'Accept' button.
-   This will display a successful message of 'Code received. Please close this window, the action
    will continue to get new token.' on the browser tab.
-   Finally, close the browser tab and come back to the 'Test Connectivity' browser tab. The pop-up
    window should display a 'Test Connectivity Passed' message.

## Non Interactive Method to run Test Connectivity

-   Here make sure that the 'Non Interactive Auth' checkbox is checked in asset configuration.
-   Click on the 'TEST CONNECTIVITY' button, it should run the test connectivity action without any
    user interaction.

## Explanation of Test Connectivity Workflow for Interactive auth and Non Interactive auth

-   This app uses (version 1.0) OAUTH 2.0 authorization code workflow APIs for generating the
    \[access_token\] and \[refresh_token\] pairs if the authentication method is interactive else
    \[access_token\] if authentication method is non interactive is used for all the API calls to
    the Defender ATP instance.

-   Interactive authentication mechanism is a user-context based workflow and the permissions of the
    user also matter along with the API permissions set to define the scope and permissions of the
    generated tokens. For more information visit the link mentioned here for the [OAUTH 2.0 AUTH
    CODE](https://docs.microsoft.com/en-gb/azure/active-directory/azuread-dev/v1-protocols-oauth-code)
    .

-   Non Interactive authentication mechanism is a user-context based workflow and the permissions of
    the user also matter along with the API permissions set to define the scope and permissions of
    the generated token. For more information visit the link mentioned here for the [OAUTH 2.0
    CLIENT
    CREDENTIALS](https://docs.microsoft.com/en-gb/azure/active-directory/azuread-dev/v1-oauth2-client-creds-grant-flow)
    .

-   The step-by-step process for the entire authentication mechanism is explained below.

      

    -   The first step is to get an application created in a specific tenant on the Microsoft Azure
        Active Directory. Generate the \[client_secret\] for the configured application. The
        detailed steps have been mentioned in the earlier section.

    -   Configure the Windows Defender ATP app's asset with appropriate values for \[tenant_id\],
        \[client_id\], and \[client_secret\] configuration parameters.

    -   Run the test connectivity action for Interactive method.

          

        -   Internally, the connectivity creates a URL for hitting the /authorize endpoint for the
            generation of the authorization code and displays it on the connectivity pop-up window.
            The user is requested to hit this URL in a browser new tab and complete the
            authorization request successfully resulting in the generation of an authorization code.
        -   The authorization code generated in the above step is used by the connectivity to make
            the next API call to generate the \[access_token\] and \[refresh_token\] pair. The
            generated authorization code, \[access_token\], and \[refresh_token\] are stored in the
            state file of the app on the Splunk SOAR server.
        -   The authorization code can be used only once to generate the pair of \[access_token\]
            and \[refresh_token\]. If the \[access_token\] expires, then the \[refresh_token\] is
            used internally automatically by the application to re-generate the \[access_token\] by
            making the corresponding API call. This entire autonomous workflow will seamlessly work
            until the \[refresh_token\] does not get expired. Once the \[refresh_token\] expires,
            the user will have to run the test connectivity action once again to generate the
            authorization code followed by the generation of an entirely fresh pair of
            \[access_token\] and \[refresh_token\]. The default expiration time for the
            \[access_token\] is 1 hour and that of the \[refresh_token\] is 90 days. For more
            details visit [AD Configurable Token
            Lifetimes](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-configurable-token-lifetimes)
        -   The successful run of the Test Connectivity ensures that a valid pair of
            \[access_token\] and \[refresh_token\] has been generated and stored in the app's state
            file. These tokens will be used in all the actions' execution flow to authorize their
            API calls to the Defender ATP instance.

    -   Run the test connectivity action for Non Interactive method.

          

        -   Internally, the application authenticates to Azure AD token issuance endpoint and
            requests an \[access_token\] then it will generate the \[access_token\].
        -   The \[access_token\] generated in the above step is used by the test connectivity to
            make the next API call to verify the \[access_token\]. The generated \[access_token\] is
            stored in the state file of the app on the Splunk SOAR server.
        -   If the \[access_token\] expires, then application will automatically re-generate the
            \[access_token\] by making the corresponding API call.
        -   The successful run of the Test Connectivity ensures that a valid \[access_token\] has
            been generated and stored in the app's state file. This token will be used in all the
            actions execution flow to authorize their API calls to the Defender ATP instance.

## State file permissions

Please check the permissions for the state file as mentioned below.

#### State file path

-   For Non-NRI instance: /opt/phantom/local_data/app_states/\<appid>/\<asset_id>\_state.json
-   For NRI instance:
    /\<PHANTOM_HOME_DIRECTORY>/local_data/app_states/\<appid>/\<asset_id>\_state.json

#### State file permissions

-   File rights: rw-rw-r-- (664) (The Splunk SOAR user should have read and write access for the
    state file)
-   File owner: Appropriate Splunk SOAR user

## Notes

-   \<appid> - The app ID will be available in the Redirect URI which gets populated in the field
    'POST incoming for Windows Defender ATP to this location' when the Defender ATP Splunk SOAR app
    asset is configured e.g.
    https://\<splunk_soar_host>/rest/handler/windowsdefenderatp\_\<appid>/\<asset_name>/result
-   \<asset_id> - The asset ID will be available on the created asset's Splunk SOAR web URL e.g.
    https://\<splunk_soar_host>/apps/\<app_number>/asset/\<asset_id>/

## get file (live response) action workflow

-   There can be four different cases based on the provided parameters:

      

    -   Case 1:

          

        -   Only event_id is provided - In this case, the rest of the parameters will be ignored and
            the action will try to get the file based on the provided **event_id** . The action can
            get the file only if the status received from the **get_status** action for the given
            event_id is **Succeeded** (How the event_id is generated is mentioned in the next Case).

    -   Case 2:

          

        -   No event_id is provided and other parameters are provided - In this case, **device_id,
            file_path and comment** all the three parameters are required. If the timeout is not
            provided, the default timeout value is considered as 300 seconds. In the given timeout,
            the action will try to get the file and if action takes longer time than the given
            timeout, it will provide an **event_id** and **file_status** . The event_id can be used
            in the **get_status** action to receive the status and once the status is **Succeeded**
            , the same event_id can be used in this action to get the file into the vault (Case 1).

    -   Case 3:

          

        -   Both event_id and other parameters are provided - In this case, the event_id will get
            the higher priority and the action will try to get the file based on the **event_id**
            (Case 1). If the action fails to get the file using event_id, it will look into other
            parameters and it will work in the same way as mentioned in Case 2.

    -   Case 4:

          

        -   No parameters are provided - In this case the action will fail, because either
            **event_id** or **Other parameters (file_path, device_id, and comment)** are required in
            order to get the file.

## run script (live response) action workflow

-   There can be four different cases based on the provided parameters:

      

    -   Case 1:

          

        -   Only event_id is provided - In this case, the rest of the parameters will be ignored and
            the action will try to get the script output based on the provided **event_id** . The
            action can get the script output if the status received from the **get_status** action
            for the given event_id is **Succeeded** (How the event_id is generated is mentioned in
            the next Case.)

    -   Case 2:

          

        -   No event_id provided and other parameters are provided - In this case, **device_id,
            script_name and comment** all the three parameters are required. If the timeout is not
            provided, the default timeout value is considered as 300 seconds. In the given timeout,
            the action will try to execute the script and provide the output and if the action takes
            longer time than the given timeout, it will provide an **event_id** and
            **script_status** . The event_id can be used in the **get_status** action to receive the
            status and once the status is **Succeeded** , the same event_id can be used in this
            action to get the script output (Case 1).

    -   Case 3:

          

        -   Both event_id and other parameters are provided - In this case the event_id will get the
            higher priority and the action will try to get the script output based on the
            **event_id** (Case 1). If the action fails to get the script output using event_id, it
            will look into other parameters and it will work in the same way as mentioned in Case 2.

    -   Case 4:

          

        -   No parameters are provided - In this case the action will fail, because either
            **event_id** or **Other parameters (script_name, device_id, and comment)** are required
            in order to get the script output.

#### The app is configured and ready to be used now.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Windows Defender ATP asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**tenant\_id** |  required  | string | Tenant ID
**client\_id** |  required  | string | Client ID
**client\_secret** |  required  | password | Client Secret
**non\_interactive** |  optional  | boolean | Non Interactive Auth
**environment** |  required  | string | Azure environment to connect

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using the supplied configuration  
[quarantine device](#action-quarantine-device) - Quarantine the device  
[unquarantine device](#action-unquarantine-device) - Unquarantine the device  
[get status](#action-get-status) - Get status of the event on a machine  
[scan device](#action-scan-device) - Scan a device for virus  
[quarantine file](#action-quarantine-file) - Quarantine a file  
[list devices](#action-list-devices) - List of recently seen devices  
[list alerts](#action-list-alerts) - List all alerts of a given type  
[list sessions](#action-list-sessions) - List all logged in users on a machine  
[get alert](#action-get-alert) - Retrieve specific Alert by its ID  
[update alert](#action-update-alert) - Update properties of existing Alert  
[domain prevalence](#action-domain-prevalence) - Return statistics for the specified domain  
[ip prevalence](#action-ip-prevalence) - Return statistics for the specified IP  
[file prevalence](#action-file-prevalence) - Return statistics for the specified file  
[get file info](#action-get-file-info) - Retrieve a File information by identifier SHA1, or SHA256  
[get file devices](#action-get-file-devices) - Retrieve a collection of devices related to a given file hash \(SHA1\)  
[get user devices](#action-get-user-devices) - Retrieve a collection of devices related to a given user ID  
[get installed software](#action-get-installed-software) - Retrieve a collection of installed software related to a given device ID  
[restrict app execution](#action-restrict-app-execution) - Restrict execution of all applications on the device except a predefined set  
[list indicators](#action-list-indicators) - Retrieve a collection of all active Indicators  
[submit indicator](#action-submit-indicator) - Submit or Update new Indicator entity  
[delete indicator](#action-delete-indicator) - Delete an Indicator entity by ID  
[run query](#action-run-query) - An advanced search query  
[get domain devices](#action-get-domain-devices) - Retrieve a collection of devices that have communicated to or from a given domain address  
[update device tag](#action-update-device-tag) - Add or remove a tag from a given device \(Maximum\: 200 characters\)  
[get discovered vulnerabilities](#action-get-discovered-vulnerabilities) - Retrieve a collection of discovered vulnerabilities related to a given device ID  
[remove app restriction](#action-remove-app-restriction) - Enable execution of any application on the device  
[get exposure score](#action-get-exposure-score) - Retrieve the organizational exposure score  
[get secure score](#action-get-secure-score) - Retrieve your Microsoft Secure Score for devices  
[get file](#action-get-file) - Download a file from a device using live response  
[put file](#action-put-file) - Put a file from the library to a device using live response  
[run script](#action-run-script) - Run a script from the library on a device using live response  
[get missing kbs](#action-get-missing-kbs) - Retrieve missing KBs \(security updates\) by given device ID  

## action: 'test connectivity'
Validate the asset configuration for connectivity using the supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'quarantine device'
Quarantine the device

Type: **contain**  
Read only: **False**

This action can take a while to complete execution\. The action retries at an interval of 5 seconds within a specified <b>timeout</b> to check if event execution is complete\. If not, the action would return the latest status of the event along with the event ID\.<br>The <b>get status</b> action can be used to fetch the latest status of the event with the event ID\.<br>For parameter <i>type</i>, <b>&quotFull&quot</b> will completely quarantine the device while <b>&quotSelective&quot</b> will allow Skype and Outlook to be accessed\.<br>The maximum timeout period for a status check is 10 minutes\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | ID of the device to quarantine | string |  `defender atp device id` 
**type** |  required  | Type of quarantine \(Default\: Full\) | string | 
**comment** |  required  | Comment for quarantine | string | 
**timeout** |  optional  | Timeout in seconds \(Default\: 30\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.device\_id | string |  `defender atp device id` 
action\_result\.parameter\.timeout | numeric | 
action\_result\.parameter\.type | string | 
action\_result\.data\.\*\.\@odata\.context | string |  `url` 
action\_result\.data\.\*\.cancellationComment | string | 
action\_result\.data\.\*\.cancellationDateTimeUtc | string | 
action\_result\.data\.\*\.cancellationRequestor | string | 
action\_result\.data\.\*\.computerDnsName | string | 
action\_result\.data\.\*\.creationDateTimeUtc | string | 
action\_result\.data\.\*\.error | string | 
action\_result\.data\.\*\.errorHResult | numeric | 
action\_result\.data\.\*\.externalId | string | 
action\_result\.data\.\*\.id | string |  `defender atp event id` 
action\_result\.data\.\*\.lastUpdateDateTimeUtc | string | 
action\_result\.data\.\*\.machineId | string |  `defender atp device id` 
action\_result\.data\.\*\.relatedFileInfo | string | 
action\_result\.data\.\*\.requestSource | string | 
action\_result\.data\.\*\.requestor | string |  `email` 
action\_result\.data\.\*\.requestorComment | string | 
action\_result\.data\.\*\.scope | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.troubleshootInfo | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.event\_id | string |  `defender atp event id` 
action\_result\.summary\.quarantine\_status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unquarantine device'
Unquarantine the device

Type: **correct**  
Read only: **False**

This action can take a while to complete execution\. The action retries at an interval of 5 seconds within a specified <b>timeout</b> to check if event execution is complete\. If not, the action would return the latest status of the event along with the event ID\.<br>The <b>get status</b> action can be used to fetch the latest status of the event with the event ID\.<br>The maximum timeout period for a status check is 10 minutes\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | ID of the device to unquarantine | string |  `defender atp device id` 
**comment** |  required  | Comment for unquarantine | string | 
**timeout** |  optional  | Timeout in seconds \(Default\: 30\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.device\_id | string |  `defender atp device id` 
action\_result\.parameter\.timeout | numeric | 
action\_result\.data\.\*\.\@odata\.context | string |  `url` 
action\_result\.data\.\*\.cancellationComment | string | 
action\_result\.data\.\*\.cancellationDateTimeUtc | string | 
action\_result\.data\.\*\.cancellationRequestor | string | 
action\_result\.data\.\*\.computerDnsName | string | 
action\_result\.data\.\*\.creationDateTimeUtc | string | 
action\_result\.data\.\*\.error | string | 
action\_result\.data\.\*\.errorHResult | numeric | 
action\_result\.data\.\*\.externalId | string | 
action\_result\.data\.\*\.id | string |  `defender atp event id` 
action\_result\.data\.\*\.lastUpdateDateTimeUtc | string | 
action\_result\.data\.\*\.machineId | string |  `defender atp device id` 
action\_result\.data\.\*\.relatedFileInfo | string | 
action\_result\.data\.\*\.requestSource | string | 
action\_result\.data\.\*\.requestor | string |  `email` 
action\_result\.data\.\*\.requestorComment | string | 
action\_result\.data\.\*\.scope | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.troubleshootInfo | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.event\_id | string |  `defender atp event id` 
action\_result\.summary\.unquarantine\_status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get status'
Get status of the event on a machine

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**event\_id** |  required  | ID of the event | string |  `defender atp event id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.event\_id | string |  `defender atp event id` 
action\_result\.data\.\*\.\@odata\.context | string |  `url` 
action\_result\.data\.\*\.cancellationComment | string | 
action\_result\.data\.\*\.cancellationDateTimeUtc | string | 
action\_result\.data\.\*\.cancellationRequestor | string | 
action\_result\.data\.\*\.commands\.\*\.command\.params\.\*\.key | string | 
action\_result\.data\.\*\.commands\.\*\.command\.params\.\*\.value | string | 
action\_result\.data\.\*\.commands\.\*\.command\.type | string | 
action\_result\.data\.\*\.commands\.\*\.commandStatus | string | 
action\_result\.data\.\*\.commands\.\*\.endTime | string | 
action\_result\.data\.\*\.commands\.\*\.index | numeric | 
action\_result\.data\.\*\.commands\.\*\.startTime | string | 
action\_result\.data\.\*\.computerDnsName | string | 
action\_result\.data\.\*\.creationDateTimeUtc | string | 
action\_result\.data\.\*\.error | string | 
action\_result\.data\.\*\.errorHResult | numeric | 
action\_result\.data\.\*\.externalId | string | 
action\_result\.data\.\*\.fileInstances | string | 
action\_result\.data\.\*\.id | string |  `defender atp event id` 
action\_result\.data\.\*\.lastUpdateDateTimeUtc | string | 
action\_result\.data\.\*\.machineId | string |  `defender atp device id` 
action\_result\.data\.\*\.relatedFileInfo | string | 
action\_result\.data\.\*\.relatedFileInfo\.fileIdentifier | string |  `sha1` 
action\_result\.data\.\*\.relatedFileInfo\.fileIdentifierType | string | 
action\_result\.data\.\*\.requestSource | string | 
action\_result\.data\.\*\.requestor | string |  `email` 
action\_result\.data\.\*\.requestorComment | string | 
action\_result\.data\.\*\.scope | string | 
action\_result\.data\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.troubleshootInfo | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.event\_status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'scan device'
Scan a device for virus

Type: **investigate**  
Read only: **True**

This action can take a while to complete execution\. The action retries at an interval of 5 seconds within a specified <b>timeout</b> to check if event execution is complete\. If not, the action would return the latest status of the event along with the event ID\.<br>The <b>get status</b> action can be used to fetch the latest status of the event with the event ID\.<br>The maximum timeout period for a status check is 1 hour\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | ID of the device to scan | string |  `defender atp device id` 
**scan\_type** |  required  | Type of scan | string | 
**comment** |  required  | Comment for scan | string | 
**timeout** |  optional  | Timeout in seconds \(Default\: 30\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.device\_id | string |  `defender atp device id` 
action\_result\.parameter\.scan\_type | string | 
action\_result\.parameter\.timeout | numeric | 
action\_result\.data\.\*\.\@odata\.context | string |  `url` 
action\_result\.data\.\*\.cancellationComment | string | 
action\_result\.data\.\*\.cancellationDateTimeUtc | string | 
action\_result\.data\.\*\.cancellationRequestor | string | 
action\_result\.data\.\*\.computerDnsName | string | 
action\_result\.data\.\*\.creationDateTimeUtc | string | 
action\_result\.data\.\*\.error | string | 
action\_result\.data\.\*\.errorHResult | numeric | 
action\_result\.data\.\*\.externalId | string | 
action\_result\.data\.\*\.id | string |  `defender atp event id` 
action\_result\.data\.\*\.lastUpdateDateTimeUtc | string | 
action\_result\.data\.\*\.machineId | string |  `defender atp device id` 
action\_result\.data\.\*\.relatedFileInfo | string | 
action\_result\.data\.\*\.requestSource | string | 
action\_result\.data\.\*\.requestor | string |  `email` 
action\_result\.data\.\*\.requestorComment | string | 
action\_result\.data\.\*\.scope | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.troubleshootInfo | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.event\_id | string |  `defender atp event id` 
action\_result\.summary\.scan\_status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'quarantine file'
Quarantine a file

Type: **contain**  
Read only: **False**

This action can take a while to complete execution\. The action retries at an interval of 5 seconds within a specified <b>timeout</b> to check if event execution is complete\. If not, the action would return the latest status of the event along with the event ID\.<br>The <b>get status</b> action can be used to fetch the latest status of the event with the event ID\.<br>The maximum timeout period for a status check is 10 minutes\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | ID of the device | string |  `defender atp device id` 
**file\_hash** |  required  | Identifier of the file | string |  `sha1` 
**comment** |  required  | Comment for quarantine | string | 
**timeout** |  optional  | Timeout in seconds \(Default\: 30\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.device\_id | string |  `defender atp device id` 
action\_result\.parameter\.file\_hash | string |  `sha1` 
action\_result\.parameter\.timeout | numeric | 
action\_result\.data\.\*\.\@odata\.context | string |  `url` 
action\_result\.data\.\*\.cancellationComment | string | 
action\_result\.data\.\*\.cancellationDateTimeUtc | string | 
action\_result\.data\.\*\.cancellationRequestor | string | 
action\_result\.data\.\*\.computerDnsName | string | 
action\_result\.data\.\*\.creationDateTimeUtc | string | 
action\_result\.data\.\*\.error | string | 
action\_result\.data\.\*\.errorHResult | numeric | 
action\_result\.data\.\*\.externalId | string | 
action\_result\.data\.\*\.fileId | string |  `sha1` 
action\_result\.data\.\*\.fileInstances\.\*\.filePath | string |  `file path` 
action\_result\.data\.\*\.fileInstances\.\*\.status | string | 
action\_result\.data\.\*\.id | string |  `defender atp event id` 
action\_result\.data\.\*\.lastUpdateDateTimeUtc | string | 
action\_result\.data\.\*\.machineId | string |  `defender atp device id` 
action\_result\.data\.\*\.relatedFileInfo\.fileIdentifier | string |  `sha1` 
action\_result\.data\.\*\.relatedFileInfo\.fileIdentifierType | string | 
action\_result\.data\.\*\.requestSource | string | 
action\_result\.data\.\*\.requestor | string |  `email` 
action\_result\.data\.\*\.requestorComment | string | 
action\_result\.data\.\*\.scope | string | 
action\_result\.data\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.troubleshootInfo | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.event\_id | string |  `defender atp event id` 
action\_result\.summary\.quarantine\_status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list devices'
List of recently seen devices

Type: **investigate**  
Read only: **True**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/windows/security/threat\-protection/microsoft\-defender\-atp/get\-machines" target="\_blank">List Machines API Documentation</a>\), the user can get devices last seen in the past 30 days; the maximum page size is 10,000; rate limitations for this action are 100 calls per minute and 1500 calls per hour\. If the user does not specify the limit value, it will fetch 100 devices by default\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**input\_type** |  required  | Type of input \(Default\: All\) | string | 
**input** |  optional  | Input filter of type Domain, File hash or All | string |  `sha1`  `sha256`  `md5`  `domain` 
**query** |  optional  | Additional OData V4 filters to apply | string | 
**limit** |  optional  | Maximum number of devices to return \(Maximum\: 10,000\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.input | string |  `sha1`  `sha256`  `md5`  `domain` 
action\_result\.parameter\.input\_type | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.query | string | 
action\_result\.data\.\*\.aadDeviceId | string | 
action\_result\.data\.\*\.agentVersion | string | 
action\_result\.data\.\*\.computerDnsName | string |  `domain` 
action\_result\.data\.\*\.defenderAvStatus | string | 
action\_result\.data\.\*\.deviceValue | string | 
action\_result\.data\.\*\.exposureLevel | string | 
action\_result\.data\.\*\.firstSeen | string | 
action\_result\.data\.\*\.groupName | string | 
action\_result\.data\.\*\.healthStatus | string | 
action\_result\.data\.\*\.id | string |  `defender atp device id` 
action\_result\.data\.\*\.ipAddresses\.\*\.ipAddress | string | 
action\_result\.data\.\*\.ipAddresses\.\*\.macAddress | string | 
action\_result\.data\.\*\.ipAddresses\.\*\.operationalStatus | string | 
action\_result\.data\.\*\.ipAddresses\.\*\.type | string | 
action\_result\.data\.\*\.isAadJoined | boolean | 
action\_result\.data\.\*\.lastExternalIpAddress | string |  `ip` 
action\_result\.data\.\*\.lastIpAddress | string |  `ip` 
action\_result\.data\.\*\.lastSeen | string | 
action\_result\.data\.\*\.machineTags | string | 
action\_result\.data\.\*\.managedBy | string | 
action\_result\.data\.\*\.managedByStatus | string | 
action\_result\.data\.\*\.onboardingStatus | string | 
action\_result\.data\.\*\.osArchitecture | string | 
action\_result\.data\.\*\.osBuild | numeric | 
action\_result\.data\.\*\.osPlatform | string | 
action\_result\.data\.\*\.osProcessor | string | 
action\_result\.data\.\*\.osVersion | string | 
action\_result\.data\.\*\.rbacGroupId | numeric | 
action\_result\.data\.\*\.rbacGroupName | string | 
action\_result\.data\.\*\.riskScore | string | 
action\_result\.data\.\*\.systemProductName | string | 
action\_result\.data\.\*\.version | string | 
action\_result\.data\.\*\.vmMetadata | string | 
action\_result\.data\.\*\.vmMetadata\.cloudProvider | string | 
action\_result\.data\.\*\.vmMetadata\.resourceId | string | 
action\_result\.data\.\*\.vmMetadata\.subscriptionId | string | 
action\_result\.data\.\*\.vmMetadata\.vmId | string | 
action\_result\.summary\.total\_devices | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list alerts'
List all alerts of a given type

Type: **investigate**  
Read only: **True**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/windows/security/threat\-protection/microsoft\-defender\-atp/get\-alerts" target="\_blank">List Alerts API Documentation</a>\), the user can get alerts last updated in the past 30 days; the maximum page size is 10,000; rate limitations for this action are 100 calls per minute and 1500 calls per hour\. If the user does not specify the limit value, it will fetch 100 alerts by default\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**input\_type** |  optional  | Type of input \(Default\: All\) | string | 
**input** |  optional  | Input filter of type Domain, File Hash, and IP | string |  `domain`  `sha1`  `sha256`  `md5`  `ip` 
**limit** |  optional  | Maximum number of alerts to return \(Maximum\: 10,000\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.input | string |  `domain`  `sha1`  `sha256`  `md5`  `ip` 
action\_result\.parameter\.input\_type | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.aadTenantId | string | 
action\_result\.data\.\*\.alertCreationTime | string | 
action\_result\.data\.\*\.assignedTo | string |  `email` 
action\_result\.data\.\*\.category | string | 
action\_result\.data\.\*\.classification | string | 
action\_result\.data\.\*\.comments\.\*\.comment | string | 
action\_result\.data\.\*\.comments\.\*\.createdBy | string |  `email` 
action\_result\.data\.\*\.comments\.\*\.createdTime | string | 
action\_result\.data\.\*\.computerDnsName | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.detectionSource | string | 
action\_result\.data\.\*\.detectorId | string | 
action\_result\.data\.\*\.determination | string | 
action\_result\.data\.\*\.evidence\.\*\.aadUserId | string | 
action\_result\.data\.\*\.evidence\.\*\.accountName | string | 
action\_result\.data\.\*\.evidence\.\*\.detectionStatus | string | 
action\_result\.data\.\*\.evidence\.\*\.domainName | string | 
action\_result\.data\.\*\.evidence\.\*\.entityType | string | 
action\_result\.data\.\*\.evidence\.\*\.evidenceCreationTime | string | 
action\_result\.data\.\*\.evidence\.\*\.fileName | string | 
action\_result\.data\.\*\.evidence\.\*\.filePath | string | 
action\_result\.data\.\*\.evidence\.\*\.ipAddress | string | 
action\_result\.data\.\*\.evidence\.\*\.parentProcessCreationTime | string | 
action\_result\.data\.\*\.evidence\.\*\.parentProcessFileName | string | 
action\_result\.data\.\*\.evidence\.\*\.parentProcessFilePath | string | 
action\_result\.data\.\*\.evidence\.\*\.parentProcessId | string | 
action\_result\.data\.\*\.evidence\.\*\.processCommandLine | string | 
action\_result\.data\.\*\.evidence\.\*\.processCreationTime | string | 
action\_result\.data\.\*\.evidence\.\*\.processId | string | 
action\_result\.data\.\*\.evidence\.\*\.registryHive | string | 
action\_result\.data\.\*\.evidence\.\*\.registryKey | string | 
action\_result\.data\.\*\.evidence\.\*\.registryValue | string | 
action\_result\.data\.\*\.evidence\.\*\.registryValueName | string | 
action\_result\.data\.\*\.evidence\.\*\.registryValueType | string | 
action\_result\.data\.\*\.evidence\.\*\.sha1 | string | 
action\_result\.data\.\*\.evidence\.\*\.sha256 | string | 
action\_result\.data\.\*\.evidence\.\*\.url | string | 
action\_result\.data\.\*\.evidence\.\*\.userPrincipalName | string | 
action\_result\.data\.\*\.evidence\.\*\.userSid | string | 
action\_result\.data\.\*\.firstEventTime | string | 
action\_result\.data\.\*\.id | string |  `defender atp alert id` 
action\_result\.data\.\*\.incidentId | numeric | 
action\_result\.data\.\*\.investigationId | numeric | 
action\_result\.data\.\*\.investigationState | string | 
action\_result\.data\.\*\.lastEventTime | string | 
action\_result\.data\.\*\.lastUpdateTime | string | 
action\_result\.data\.\*\.loggedOnUsers\.\*\.accountName | string | 
action\_result\.data\.\*\.loggedOnUsers\.\*\.domainName | string | 
action\_result\.data\.\*\.machineId | string |  `defender atp device id` 
action\_result\.data\.\*\.rbacGroupName | string | 
action\_result\.data\.\*\.recommendedAction | string | 
action\_result\.data\.\*\.relatedUser | string | 
action\_result\.data\.\*\.relatedUser\.domainName | string | 
action\_result\.data\.\*\.relatedUser\.userName | string | 
action\_result\.data\.\*\.resolvedTime | string | 
action\_result\.data\.\*\.severity | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.threatFamilyName | string | 
action\_result\.data\.\*\.threatName | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.summary\.total\_alerts | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list sessions'
List all logged in users on a machine

Type: **investigate**  
Read only: **True**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/windows/security/threat\-protection/microsoft\-defender\-atp/get\-machine\-log\-on\-users" target="\_blank">List Sessions API Documentation</a>\), the user can query on machines last seen in the past 30 days; rate limitations for this action are 100 calls per minute and 1500 calls per hour\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | ID of the device | string |  `defender atp device id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.device\_id | string |  `defender atp device id` 
action\_result\.data\.\*\.accountDomain | string |  `domain` 
action\_result\.data\.\*\.accountDomainName | string |  `domain` 
action\_result\.data\.\*\.accountName | string | 
action\_result\.data\.\*\.accountSid | string | 
action\_result\.data\.\*\.firstSeen | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.isDomainAdmin | boolean | 
action\_result\.data\.\*\.isOnlyNetworkUser | string | 
action\_result\.data\.\*\.lastSeen | string | 
action\_result\.data\.\*\.leastPrevalentMachineId | string |  `sha1` 
action\_result\.data\.\*\.logOnMachinesCount | numeric | 
action\_result\.data\.\*\.logonTypes | string | 
action\_result\.data\.\*\.mostPrevalentMachineId | string |  `sha1` 
action\_result\.summary\.total\_sessions | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get alert'
Retrieve specific Alert by its ID

Type: **investigate**  
Read only: **True**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/get\-alert\-info\-by\-id" target="\_blank">Get Alert Information by ID API Documentation</a>\), user can get alerts last updated according to your configured retention period\.; rate limitations for this action are 100 calls per minute and 1500 calls per hour\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert\_id** |  required  | ID of the alert | string |  `defender atp alert id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.alert\_id | string |  `defender atp alert id` 
action\_result\.data\.\*\.\@odata\.context | string |  `url` 
action\_result\.data\.\*\.aadTenantId | string | 
action\_result\.data\.\*\.alertCreationTime | string | 
action\_result\.data\.\*\.assignedTo | string | 
action\_result\.data\.\*\.category | string | 
action\_result\.data\.\*\.classification | string | 
action\_result\.data\.\*\.comments\.\*\.comment | string | 
action\_result\.data\.\*\.comments\.\*\.createdBy | string | 
action\_result\.data\.\*\.comments\.\*\.createdTime | string | 
action\_result\.data\.\*\.computerDnsName | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.detectionSource | string | 
action\_result\.data\.\*\.detectorId | string | 
action\_result\.data\.\*\.determination | string | 
action\_result\.data\.\*\.evidence\.\*\.aadUserId | string | 
action\_result\.data\.\*\.evidence\.\*\.accountName | string | 
action\_result\.data\.\*\.evidence\.\*\.detectionStatus | string | 
action\_result\.data\.\*\.evidence\.\*\.domainName | string |  `domain` 
action\_result\.data\.\*\.evidence\.\*\.entityType | string | 
action\_result\.data\.\*\.evidence\.\*\.evidenceCreationTime | string | 
action\_result\.data\.\*\.evidence\.\*\.fileName | string |  `file name` 
action\_result\.data\.\*\.evidence\.\*\.filePath | string |  `file path` 
action\_result\.data\.\*\.evidence\.\*\.ipAddress | string |  `ip` 
action\_result\.data\.\*\.evidence\.\*\.parentProcessCreationTime | string | 
action\_result\.data\.\*\.evidence\.\*\.parentProcessFileName | string | 
action\_result\.data\.\*\.evidence\.\*\.parentProcessFilePath | string | 
action\_result\.data\.\*\.evidence\.\*\.parentProcessId | string |  `pid` 
action\_result\.data\.\*\.evidence\.\*\.processCommandLine | string | 
action\_result\.data\.\*\.evidence\.\*\.processCreationTime | string | 
action\_result\.data\.\*\.evidence\.\*\.processId | string |  `pid` 
action\_result\.data\.\*\.evidence\.\*\.registryHive | string | 
action\_result\.data\.\*\.evidence\.\*\.registryKey | string | 
action\_result\.data\.\*\.evidence\.\*\.registryValue | string | 
action\_result\.data\.\*\.evidence\.\*\.registryValueName | string | 
action\_result\.data\.\*\.evidence\.\*\.registryValueType | string | 
action\_result\.data\.\*\.evidence\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.evidence\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.evidence\.\*\.url | string | 
action\_result\.data\.\*\.evidence\.\*\.userPrincipalName | string | 
action\_result\.data\.\*\.evidence\.\*\.userSid | string | 
action\_result\.data\.\*\.firstEventTime | string | 
action\_result\.data\.\*\.id | string |  `defender atp alert id` 
action\_result\.data\.\*\.incidentId | numeric | 
action\_result\.data\.\*\.investigationId | numeric | 
action\_result\.data\.\*\.investigationState | string | 
action\_result\.data\.\*\.lastEventTime | string | 
action\_result\.data\.\*\.lastUpdateTime | string | 
action\_result\.data\.\*\.loggedOnUsers\.\*\.accountName | string | 
action\_result\.data\.\*\.loggedOnUsers\.\*\.domainName | string | 
action\_result\.data\.\*\.machineId | string |  `defender atp device id` 
action\_result\.data\.\*\.rbacGroupName | string | 
action\_result\.data\.\*\.relatedUser | string | 
action\_result\.data\.\*\.relatedUser\.domainName | string | 
action\_result\.data\.\*\.relatedUser\.userName | string | 
action\_result\.data\.\*\.resolvedTime | string | 
action\_result\.data\.\*\.severity | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.threatFamilyName | string | 
action\_result\.data\.\*\.threatName | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.summary\.action\_taken | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update alert'
Update properties of existing Alert

Type: **investigate**  
Read only: **False**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/update\-alert" target="\_blank">Get Alert Information by ID API Documentation</a>\), user can update alerts that available in the API\. See List Alerts for more information\. Also, previously supported alert determination values \('Apt' and 'SecurityPersonnel'\) have been deprecated and no longer available via the API; rate limitations for this action are 100 calls per minute and 1500 calls per hour\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert\_id** |  required  | ID of the alert | string |  `defender atp alert id` 
**status** |  optional  | Specifies the current status of the alert | string | 
**assigned\_to** |  optional  | Owner of the alert | string |  `email` 
**classification** |  optional  | Specifies the specification of the alert | string | 
**determination** |  optional  | Specifies the determination of the alert | string | 
**comment** |  optional  | Comment to be added to the alert | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.alert\_id | string |  `defender atp alert id` 
action\_result\.parameter\.assigned\_to | string |  `email` 
action\_result\.parameter\.classification | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.determination | string | 
action\_result\.parameter\.status | string | 
action\_result\.data\.\*\.\@odata\.context | string |  `url` 
action\_result\.data\.\*\.aadTenantId | string | 
action\_result\.data\.\*\.alertCreationTime | string | 
action\_result\.data\.\*\.assignedTo | string |  `email` 
action\_result\.data\.\*\.category | string | 
action\_result\.data\.\*\.classification | string | 
action\_result\.data\.\*\.comments\.\*\.comment | string | 
action\_result\.data\.\*\.comments\.\*\.createdBy | string | 
action\_result\.data\.\*\.comments\.\*\.createdTime | string | 
action\_result\.data\.\*\.computerDnsName | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.detectionSource | string | 
action\_result\.data\.\*\.detectorId | string | 
action\_result\.data\.\*\.determination | string | 
action\_result\.data\.\*\.evidence\.\*\.aadUserId | string | 
action\_result\.data\.\*\.evidence\.\*\.accountName | string | 
action\_result\.data\.\*\.evidence\.\*\.detectionStatus | string | 
action\_result\.data\.\*\.evidence\.\*\.domainName | string |  `domain` 
action\_result\.data\.\*\.evidence\.\*\.entityType | string | 
action\_result\.data\.\*\.evidence\.\*\.evidenceCreationTime | string | 
action\_result\.data\.\*\.evidence\.\*\.fileName | string |  `file name` 
action\_result\.data\.\*\.evidence\.\*\.filePath | string |  `file path` 
action\_result\.data\.\*\.evidence\.\*\.ipAddress | string | 
action\_result\.data\.\*\.evidence\.\*\.parentProcessCreationTime | string | 
action\_result\.data\.\*\.evidence\.\*\.parentProcessFileName | string | 
action\_result\.data\.\*\.evidence\.\*\.parentProcessFilePath | string | 
action\_result\.data\.\*\.evidence\.\*\.parentProcessId | string |  `pid` 
action\_result\.data\.\*\.evidence\.\*\.processCommandLine | string | 
action\_result\.data\.\*\.evidence\.\*\.processCreationTime | string | 
action\_result\.data\.\*\.evidence\.\*\.processId | string |  `pid` 
action\_result\.data\.\*\.evidence\.\*\.registryHive | string | 
action\_result\.data\.\*\.evidence\.\*\.registryKey | string | 
action\_result\.data\.\*\.evidence\.\*\.registryValue | string | 
action\_result\.data\.\*\.evidence\.\*\.registryValueType | string | 
action\_result\.data\.\*\.evidence\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.evidence\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.evidence\.\*\.url | string |  `url` 
action\_result\.data\.\*\.evidence\.\*\.userPrincipalName | string | 
action\_result\.data\.\*\.evidence\.\*\.userSid | string | 
action\_result\.data\.\*\.firstEventTime | string | 
action\_result\.data\.\*\.id | string |  `defender atp alert id` 
action\_result\.data\.\*\.incidentId | numeric | 
action\_result\.data\.\*\.investigationId | numeric | 
action\_result\.data\.\*\.investigationState | string | 
action\_result\.data\.\*\.lastEventTime | string | 
action\_result\.data\.\*\.lastUpdateTime | string | 
action\_result\.data\.\*\.loggedOnUsers\.\*\.accountName | string | 
action\_result\.data\.\*\.loggedOnUsers\.\*\.domainName | string | 
action\_result\.data\.\*\.machineId | string |  `defender atp device id` 
action\_result\.data\.\*\.rbacGroupName | string | 
action\_result\.data\.\*\.relatedUser | string | 
action\_result\.data\.\*\.relatedUser\.domainName | string |  `domain` 
action\_result\.data\.\*\.relatedUser\.userName | string |  `user name` 
action\_result\.data\.\*\.resolvedTime | string | 
action\_result\.data\.\*\.severity | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.threatFamilyName | string | 
action\_result\.data\.\*\.threatName | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.summary\.action\_taken | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'domain prevalence'
Return statistics for the specified domain

Type: **investigate**  
Read only: **True**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/get\-domain\-statistics?view=o365\-worldwide" target="\_blank">Get domain statistics API Documentation</a>\), rate limitations for this action are 100 calls per minute and 1500 calls per hour\. The maximum value for look\_back\_hours is 720 hours \(30 days\)\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to get the statistics | string |  `domain` 
**look\_back\_hours** |  optional  | Define the hours you search back to get the statistics \(Default\: 720 hours \(30 days\)\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.parameter\.look\_back\_hours | numeric | 
action\_result\.data\.\*\.\@odata\.context | string |  `url` 
action\_result\.data\.\*\.host | string |  `domain` 
action\_result\.data\.\*\.orgFirstSeen | string | 
action\_result\.data\.\*\.orgLastSeen | string | 
action\_result\.data\.\*\.orgPrevalence | string | 
action\_result\.data\.\*\.organizationPrevalence | numeric | 
action\_result\.summary\.organization\_prevalence | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'ip prevalence'
Return statistics for the specified IP

Type: **investigate**  
Read only: **True**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/get\-ip\-statistics?view=o365\-worldwide" target="\_blank">Get IP statistics API Documentation</a>\), rate limitations for this action are 100 calls per minute and 1500 calls per hour\. The maximum value for look\_back\_hours is 720 hours \(30 days\)\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to get the statistics | string |  `ip`  `ipv6` 
**look\_back\_hours** |  optional  | Define the hours you search back to get the statistics \(Default\: 720 hours \(30 days\)\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.parameter\.look\_back\_hours | numeric | 
action\_result\.data\.\*\.\@odata\.context | string |  `url` 
action\_result\.data\.\*\.ipAddress | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.orgFirstSeen | string | 
action\_result\.data\.\*\.orgLastSeen | string | 
action\_result\.data\.\*\.orgPrevalence | string | 
action\_result\.data\.\*\.organizationPrevalence | numeric | 
action\_result\.summary\.organization\_prevalence | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'file prevalence'
Return statistics for the specified file

Type: **investigate**  
Read only: **True**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/get\-file\-statistics?view=o365\-worldwide" target="\_blank">Get File statistics API Documentation</a>\), rate limitations for this action are 100 calls per minute and 1500 calls per hour\. The maximum value for look\_back\_hours is 720 hours \(30 days\)\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file\_hash** |  required  | File hash to get the statistics \(SHA1 or SHA256\) | string |  `sha1`  `sha256` 
**look\_back\_hours** |  optional  | Define the hours you search back to get the statistics \(Default\: 720 hours \(30 days\)\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_hash | string |  `sha1`  `sha256` 
action\_result\.parameter\.look\_back\_hours | string | 
action\_result\.data\.\*\.\@odata\.context | string |  `url` 
action\_result\.data\.\*\.globalFirstObserved | string | 
action\_result\.data\.\*\.globalLastObserved | string | 
action\_result\.data\.\*\.globalPrevalence | string | 
action\_result\.data\.\*\.globallyPrevalence | numeric | 
action\_result\.data\.\*\.orgFirstSeen | string | 
action\_result\.data\.\*\.orgLastSeen | string | 
action\_result\.data\.\*\.orgPrevalence | string | 
action\_result\.data\.\*\.organizationPrevalence | numeric | 
action\_result\.data\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.topFileNames | string |  `file name` 
action\_result\.summary\.organization\_prevalence | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get file info'
Retrieve a File information by identifier SHA1, or SHA256

Type: **investigate**  
Read only: **True**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/get\-file\-information?view=o365\-worldwide" target="\_blank">Get File Information API Documentation</a>\), rate limitations for this action are 100 calls per minute and 1500 calls per hour\. The valid file identifiers are SHA1, SHA256\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file\_hash** |  required  | Identifier of the file | string |  `sha1`  `sha256` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_hash | string |  `sha1`  `sha256` 
action\_result\.data\.\*\.\@odata\.context | string |  `url` 
action\_result\.data\.\*\.determinationType | string | 
action\_result\.data\.\*\.determinationValue | string | 
action\_result\.data\.\*\.fileProductName | string | 
action\_result\.data\.\*\.filePublisher | string | 
action\_result\.data\.\*\.fileType | string | 
action\_result\.data\.\*\.globalFirstObserved | string | 
action\_result\.data\.\*\.globalLastObserved | string | 
action\_result\.data\.\*\.globalPrevalence | numeric | 
action\_result\.data\.\*\.isPeFile | boolean | 
action\_result\.data\.\*\.isValidCertificate | boolean | 
action\_result\.data\.\*\.issuer | string | 
action\_result\.data\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.signer | string | 
action\_result\.data\.\*\.signerHash | string | 
action\_result\.data\.\*\.size | numeric | 
action\_result\.summary\.global\_prevalence | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get file devices'
Retrieve a collection of devices related to a given file hash \(SHA1\)

Type: **investigate**  
Read only: **True**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/get\-file\-related\-machines?view=o365\-worldwide" target="\_blank">Get File Related Machines API Documentation</a>\), rate limitations for this action are 100 calls per minute and 1500 calls per hour\. The valid file identifier is SHA1\.<br>The action retrieves data of the last 30 days\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file\_hash** |  required  | Identifier of the file | string |  `sha1` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_hash | string |  `sha1` 
action\_result\.data\.\*\.aadDeviceId | string | 
action\_result\.data\.\*\.agentVersion | string | 
action\_result\.data\.\*\.computerDnsName | string | 
action\_result\.data\.\*\.defenderAvStatus | string |  `domain` 
action\_result\.data\.\*\.deviceValue | string | 
action\_result\.data\.\*\.exposureLevel | string | 
action\_result\.data\.\*\.firstSeen | string | 
action\_result\.data\.\*\.healthStatus | string | 
action\_result\.data\.\*\.id | string |  `defender atp device id` 
action\_result\.data\.\*\.ipAddresses\.\*\.ipAddress | string |  `ip` 
action\_result\.data\.\*\.ipAddresses\.\*\.macAddress | string | 
action\_result\.data\.\*\.ipAddresses\.\*\.operationalStatus | string | 
action\_result\.data\.\*\.ipAddresses\.\*\.type | string | 
action\_result\.data\.\*\.isAadJoined | boolean | 
action\_result\.data\.\*\.lastExternalIpAddress | string |  `ip` 
action\_result\.data\.\*\.lastIpAddress | string |  `ip` 
action\_result\.data\.\*\.lastSeen | string | 
action\_result\.data\.\*\.managedBy | string | 
action\_result\.data\.\*\.managedByStatus | string | 
action\_result\.data\.\*\.onboardingStatus | string | 
action\_result\.data\.\*\.osArchitecture | string | 
action\_result\.data\.\*\.osBuild | numeric | 
action\_result\.data\.\*\.osPlatform | string | 
action\_result\.data\.\*\.osProcessor | string | 
action\_result\.data\.\*\.osVersion | string | 
action\_result\.data\.\*\.rbacGroupId | numeric | 
action\_result\.data\.\*\.rbacGroupName | string | 
action\_result\.data\.\*\.riskScore | string | 
action\_result\.data\.\*\.version | string | 
action\_result\.data\.\*\.vmMetadata | string | 
action\_result\.data\.\*\.vmMetadata\.cloudProvider | string | 
action\_result\.data\.\*\.vmMetadata\.resourceId | string | 
action\_result\.data\.\*\.vmMetadata\.subscriptionId | string | 
action\_result\.data\.\*\.vmMetadata\.vmId | string | 
action\_result\.summary\.total\_devices | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get user devices'
Retrieve a collection of devices related to a given user ID

Type: **investigate**  
Read only: **True**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/get\-user\-related\-machines?view=o365\-worldwide" target="\_blank">Get User Related Machines API Documentation</a>\), rate limitations for this action are 100 calls per minute and 1500 calls per hour\. The ID is not the full UPN, but only the user name\. \(for example, to retrieve machines for user1\@contoso\.com use user1 for user\_id parameter\)\.<br>The action retrieves data of the last 30 days\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_id** |  required  | ID of the user | string |  `user name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.user\_id | string |  `user name` 
action\_result\.data\.\*\.aadDeviceId | string | 
action\_result\.data\.\*\.agentVersion | string | 
action\_result\.data\.\*\.computerDnsName | string |  `domain` 
action\_result\.data\.\*\.defenderAvStatus | string | 
action\_result\.data\.\*\.deviceValue | string | 
action\_result\.data\.\*\.exposureLevel | string | 
action\_result\.data\.\*\.firstSeen | string | 
action\_result\.data\.\*\.healthStatus | string | 
action\_result\.data\.\*\.id | string |  `defender atp device id` 
action\_result\.data\.\*\.ipAddresses\.\*\.ipAddress | string |  `ip` 
action\_result\.data\.\*\.ipAddresses\.\*\.macAddress | string | 
action\_result\.data\.\*\.ipAddresses\.\*\.operationalStatus | string | 
action\_result\.data\.\*\.ipAddresses\.\*\.type | string | 
action\_result\.data\.\*\.isAadJoined | boolean | 
action\_result\.data\.\*\.lastExternalIpAddress | string |  `ip` 
action\_result\.data\.\*\.lastIpAddress | string |  `ip` 
action\_result\.data\.\*\.lastSeen | string | 
action\_result\.data\.\*\.managedBy | string | 
action\_result\.data\.\*\.managedByStatus | string | 
action\_result\.data\.\*\.onboardingStatus | string | 
action\_result\.data\.\*\.osArchitecture | string | 
action\_result\.data\.\*\.osBuild | numeric | 
action\_result\.data\.\*\.osPlatform | string | 
action\_result\.data\.\*\.osProcessor | string | 
action\_result\.data\.\*\.osVersion | string | 
action\_result\.data\.\*\.rbacGroupId | numeric | 
action\_result\.data\.\*\.rbacGroupName | string | 
action\_result\.data\.\*\.riskScore | string | 
action\_result\.data\.\*\.version | string | 
action\_result\.data\.\*\.vmMetadata | string | 
action\_result\.data\.\*\.vmMetadata\.cloudProvider | string | 
action\_result\.data\.\*\.vmMetadata\.resourceId | string | 
action\_result\.data\.\*\.vmMetadata\.subscriptionId | string | 
action\_result\.data\.\*\.vmMetadata\.vmId | string | 
action\_result\.summary\.total\_devices | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get installed software'
Retrieve a collection of installed software related to a given device ID

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | ID of the device | string |  `defender atp device id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.device\_id | string |  `defender atp device id` 
action\_result\.data\.\*\.activeAlert | boolean | 
action\_result\.data\.\*\.category | string | 
action\_result\.data\.\*\.exposedMachines | numeric | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.impactScore | numeric | 
action\_result\.data\.\*\.installedMachines | numeric | 
action\_result\.data\.\*\.isNormalized | boolean | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.publicExploit | boolean | 
action\_result\.data\.\*\.vendor | string | 
action\_result\.data\.\*\.weaknesses | numeric | 
action\_result\.summary\.total\_software | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'restrict app execution'
Restrict execution of all applications on the device except a predefined set

Type: **contain**  
Read only: **False**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/restrict\-code\-execution?view=o365\-worldwide" target="\_blank">Restrict app execution API Documentation</a>\), rate limitations for this API are 100 calls per minute and 1500 calls per hour\.<br>This action can take a while to complete execution\. The action retries at an interval of 5 seconds within a specified <b>timeout</b> to check if event execution is complete\. If not, the action would return the latest status of the event along with the event ID\.<br>The <b>get status</b> action can be used to fetch the latest status of the event with the event ID\.<br>The maximum timeout period for a status check is 1 minute\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | ID of the device | string |  `defender atp device id` 
**comment** |  required  | Comment | string | 
**timeout** |  optional  | Timeout in seconds \(Default\: 30\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.device\_id | string |  `defender atp device id` 
action\_result\.parameter\.timeout | numeric | 
action\_result\.data\.\*\.\@odata\.context | string |  `url` 
action\_result\.data\.\*\.cancellationComment | string | 
action\_result\.data\.\*\.cancellationDateTimeUtc | string | 
action\_result\.data\.\*\.cancellationRequestor | string | 
action\_result\.data\.\*\.computerDnsName | string | 
action\_result\.data\.\*\.creationDateTimeUtc | string | 
action\_result\.data\.\*\.error | string | 
action\_result\.data\.\*\.errorHResult | numeric | 
action\_result\.data\.\*\.externalId | string | 
action\_result\.data\.\*\.id | string |  `defender atp event id` 
action\_result\.data\.\*\.lastUpdateDateTimeUtc | string | 
action\_result\.data\.\*\.machineId | string |  `defender atp device id` 
action\_result\.data\.\*\.relatedFileInfo | string | 
action\_result\.data\.\*\.requestSource | string | 
action\_result\.data\.\*\.requestor | string | 
action\_result\.data\.\*\.requestorComment | string | 
action\_result\.data\.\*\.scope | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.troubleshootInfo | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.event\_id | string |  `defender atp event id` 
action\_result\.summary\.restrict\_app\_execution\_status | string | 
action\_result\.summary\.restriction\_status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list indicators'
Retrieve a collection of all active Indicators

Type: **investigate**  
Read only: **True**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/get\-ti\-indicators\-collection?view=o365\-worldwide" target="\_blank">List Indicators API Documentation</a>\), rate limitations for this action are 100 calls per minute and 1500 calls per hour\. If the user does not specify the limit value, it will fetch 100 indicators by default\. The maximum value for the limit parameter is 10000\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter** |  optional  | Additional OData V4 filters to apply | string | 
**limit** |  optional  | Maximum number of indicators to return \(Maximum\: 10,000\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.filter | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.action | string | 
action\_result\.data\.\*\.additionalInfo | string | 
action\_result\.data\.\*\.application | string | 
action\_result\.data\.\*\.bypassDurationHours | string | 
action\_result\.data\.\*\.category | numeric | 
action\_result\.data\.\*\.certificateInfo | string | 
action\_result\.data\.\*\.certificateInfo\.issuer | string | 
action\_result\.data\.\*\.certificateInfo\.serial | string | 
action\_result\.data\.\*\.certificateInfo\.sha256 | string | 
action\_result\.data\.\*\.certificateInfo\.subject | string | 
action\_result\.data\.\*\.createdBy | string | 
action\_result\.data\.\*\.createdByDisplayName | string | 
action\_result\.data\.\*\.createdBySource | string | 
action\_result\.data\.\*\.creationTimeDateTimeUtc | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.educateUrl | string | 
action\_result\.data\.\*\.expirationTime | string | 
action\_result\.data\.\*\.externalId | string | 
action\_result\.data\.\*\.generateAlert | boolean | 
action\_result\.data\.\*\.historicalDetection | boolean | 
action\_result\.data\.\*\.id | string |  `defender atp indicator id` 
action\_result\.data\.\*\.indicatorType | string | 
action\_result\.data\.\*\.indicatorValue | string |  `defender atp indicator value`  `sha1`  `sha256`  `md5`  `domain`  `ip`  `ipv6`  `url` 
action\_result\.data\.\*\.lastUpdateTime | string | 
action\_result\.data\.\*\.lastUpdatedBy | string | 
action\_result\.data\.\*\.lookBackPeriod | string | 
action\_result\.data\.\*\.notificationBody | string | 
action\_result\.data\.\*\.notificationId | string | 
action\_result\.data\.\*\.recommendedActions | string | 
action\_result\.data\.\*\.severity | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.total\_indicators | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'submit indicator'
Submit or Update new Indicator entity

Type: **generic**  
Read only: **False**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/post\-ti\-indicator?view=o365\-worldwide" target="\_blank">Submit or Update Indicator API Documentation</a>\), rate limitations for this action are 100 calls per minute and 1500 calls per hour\. There is a limit of 15,000 active indicators per tenant\.<br><b>Notes\:</b><ul><li>For the possible values of given action parameters, refer to the documentation link provided above\.<li>CIDR notation for IPs is not supported\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**title** |  required  | Indicator alert title | string | 
**description** |  required  | Description of the indicator | string | 
**indicator\_type** |  required  | Type of the indicator | string | 
**indicator\_value** |  required  | Identity of the Indicator entity | string |  `defender atp indicator value`  `sha1`  `sha256`  `md5`  `ip`  `ipv6`  `url`  `domain` 
**action** |  required  | The action that will be taken if the indicator will be discovered in the organization | string | 
**application** |  optional  | The application associated with the indicator | string | 
**expiration\_time** |  optional  | The expiration time of the indicator \(Use this format\: %Y\-%m\-%dT%H\:%M\:%SZ in UTC timezone\) | string | 
**severity** |  optional  | The severity of the indicator | string | 
**recommended\_actions** |  optional  | TI indicator alert recommended actions | string | 
**rbac\_group\_names** |  optional  | RBAC group names the indicator would be applied to \(JSON formatted list\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.action | string | 
action\_result\.parameter\.application | string | 
action\_result\.parameter\.description | string | 
action\_result\.parameter\.expiration\_time | string | 
action\_result\.parameter\.indicator\_type | string | 
action\_result\.parameter\.indicator\_value | string |  `defender atp indicator value`  `sha1`  `sha256`  `md5`  `ip`  `ipv6`  `url`  `domain` 
action\_result\.parameter\.rbac\_group\_names | string | 
action\_result\.parameter\.recommended\_actions | string | 
action\_result\.parameter\.severity | string | 
action\_result\.parameter\.title | string | 
action\_result\.data\.\*\.\@odata\.context | string |  `url` 
action\_result\.data\.\*\.action | string | 
action\_result\.data\.\*\.additionalInfo | string | 
action\_result\.data\.\*\.application | string | 
action\_result\.data\.\*\.bypassDurationHours | string | 
action\_result\.data\.\*\.category | numeric | 
action\_result\.data\.\*\.certificateInfo | string | 
action\_result\.data\.\*\.createdBy | string | 
action\_result\.data\.\*\.createdByDisplayName | string | 
action\_result\.data\.\*\.createdBySource | string | 
action\_result\.data\.\*\.creationTimeDateTimeUtc | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.educateUrl | string | 
action\_result\.data\.\*\.expirationTime | string | 
action\_result\.data\.\*\.externalId | string | 
action\_result\.data\.\*\.generateAlert | boolean | 
action\_result\.data\.\*\.historicalDetection | boolean | 
action\_result\.data\.\*\.id | string |  `defender atp indicator id` 
action\_result\.data\.\*\.indicatorType | string | 
action\_result\.data\.\*\.indicatorValue | string |  `defender atp indicator value`  `ip`  `ipv6`  `sha1`  `sha256`  `md5`  `domain`  `url` 
action\_result\.data\.\*\.lastUpdateTime | string | 
action\_result\.data\.\*\.lastUpdatedBy | string | 
action\_result\.data\.\*\.lookBackPeriod | string | 
action\_result\.data\.\*\.notificationBody | string | 
action\_result\.data\.\*\.notificationId | string | 
action\_result\.data\.\*\.recommendedActions | string | 
action\_result\.data\.\*\.severity | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.version | string | 
action\_result\.summary\.indicator\_id | string |  `defender atp indicator id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete indicator'
Delete an Indicator entity by ID

Type: **generic**  
Read only: **False**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/delete\-ti\-indicator\-by\-id?view=o365\-worldwide" target="\_blank">Delete Indicator API Documentation</a>\), rate limitations for this action are 100 calls per minute and 1500 calls per hour\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator\_id** |  required  | Indicator ID to delete | string |  `defender atp indicator id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.indicator\_id | string |  `defender atp indicator id` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'run query'
An advanced search query

Type: **investigate**  
Read only: **True**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/run\-advanced\-query\-api?view=o365\-worldwide" target="\_blank">Advanced Hunting API Documentation</a>\), <li>rate limitations for this action are 45 calls per minute and 1500 calls per hour\.</li><li>You can only run a query on data from the last 30 days\.</li><li>The execution time is 10 minutes for every hour and 3 hours of running time a day\. The maximal execution time of a single request is 10 minutes\.</li><li>The maximum query result size of a single request cannot exceed 124 MB\. If exceeded, HTTP 400 Bad Request with the message "Query execution has exceeded the allowed result size\. Optimize your query by limiting the amount of results and try again" will appear\.</li><li>The 429 response indicates that you have reached your quota limit, either in terms of requests or CPU usage\. To figure out what limit has been reached, read the response body\.</li>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Query to fetch results | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.query | string | 
action\_result\.data\.\*\.ActionType | string | 
action\_result\.data\.\*\.AntivirusEnabled | string | 
action\_result\.data\.\*\.AntivirusReporting | string | 
action\_result\.data\.\*\.AntivirusSignatureVersion | string | 
action\_result\.data\.\*\.AppGuardContainerId | string | 
action\_result\.data\.\*\.BehaviorMonitoring | string | 
action\_result\.data\.\*\.CloudProtection | string | 
action\_result\.data\.\*\.DeviceId | string |  `defender atp device id` 
action\_result\.data\.\*\.DeviceName | string | 
action\_result\.data\.\*\.DomainName | string |  `domain` 
action\_result\.data\.\*\.DurationAtLeast | string | 
action\_result\.data\.\*\.FileName | string |  `file name` 
action\_result\.data\.\*\.ImpairedCommunications | string | 
action\_result\.data\.\*\.InitiatingProcessAccountDomain | string | 
action\_result\.data\.\*\.InitiatingProcessAccountName | string | 
action\_result\.data\.\*\.InitiatingProcessAccountObjectId | string | 
action\_result\.data\.\*\.InitiatingProcessAccountSid | string | 
action\_result\.data\.\*\.InitiatingProcessAccountUpn | string | 
action\_result\.data\.\*\.InitiatingProcessCommandLine | string | 
action\_result\.data\.\*\.InitiatingProcessCreationTime | string | 
action\_result\.data\.\*\.InitiatingProcessFileName | string |  `file name` 
action\_result\.data\.\*\.InitiatingProcessFileSize | numeric | 
action\_result\.data\.\*\.InitiatingProcessFolderPath | string | 
action\_result\.data\.\*\.InitiatingProcessId | numeric | 
action\_result\.data\.\*\.InitiatingProcessIntegrityLevel | string | 
action\_result\.data\.\*\.InitiatingProcessMD5 | string | 
action\_result\.data\.\*\.InitiatingProcessParentCreationTime | string | 
action\_result\.data\.\*\.InitiatingProcessParentFileName | string | 
action\_result\.data\.\*\.InitiatingProcessParentId | numeric | 
action\_result\.data\.\*\.InitiatingProcessSHA1 | string | 
action\_result\.data\.\*\.InitiatingProcessSHA256 | string | 
action\_result\.data\.\*\.InitiatingProcessTokenElevation | string | 
action\_result\.data\.\*\.InitiatingProcessVersionInfoCompanyName | string | 
action\_result\.data\.\*\.InitiatingProcessVersionInfoFileDescription | string | 
action\_result\.data\.\*\.InitiatingProcessVersionInfoInternalFileName | string | 
action\_result\.data\.\*\.InitiatingProcessVersionInfoOriginalFileName | string | 
action\_result\.data\.\*\.InitiatingProcessVersionInfoProductName | string | 
action\_result\.data\.\*\.InitiatingProcessVersionInfoProductVersion | string | 
action\_result\.data\.\*\.LastTimestamp | string | 
action\_result\.data\.\*\.PUAProtection | string | 
action\_result\.data\.\*\.PreviousRegistryKey | string | 
action\_result\.data\.\*\.PreviousRegistryValueData | string | 
action\_result\.data\.\*\.PreviousRegistryValueName | string | 
action\_result\.data\.\*\.RealtimeProtection | string | 
action\_result\.data\.\*\.RegistryKey | string | 
action\_result\.data\.\*\.RegistryValueData | string | 
action\_result\.data\.\*\.RegistryValueName | string | 
action\_result\.data\.\*\.RegistryValueType | string | 
action\_result\.data\.\*\.ReportId | numeric | 
action\_result\.data\.\*\.SensorDataCollection | string | 
action\_result\.data\.\*\.SensorEnabled | string | 
action\_result\.data\.\*\.TamperProtection | string | 
action\_result\.data\.\*\.Timestamp | string | 
action\_result\.data\.\*\.UserName | string |  `user name` 
action\_result\.summary\.total\_results | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get domain devices'
Retrieve a collection of devices that have communicated to or from a given domain address

Type: **investigate**  
Read only: **True**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/get\-domain\-related\-machines?view=o365\-worldwide" target="\_blank">Get domain related machines API Documentation</a>\), rate limitations for this action are 100 calls per minute and 1500 calls per hour\. You can query on devices last updated according to your configured retention period\.<br>The action retrieves data of the last 30 days\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to get the devices | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data\.\*\.aadDeviceId | string | 
action\_result\.data\.\*\.agentVersion | string | 
action\_result\.data\.\*\.computerDnsName | string | 
action\_result\.data\.\*\.defenderAvStatus | string | 
action\_result\.data\.\*\.deviceValue | string | 
action\_result\.data\.\*\.exposureLevel | string | 
action\_result\.data\.\*\.firstSeen | string | 
action\_result\.data\.\*\.healthStatus | string | 
action\_result\.data\.\*\.id | string |  `defender atp device id` 
action\_result\.data\.\*\.ipAddresses\.\*\.ipAddress | string |  `ip` 
action\_result\.data\.\*\.ipAddresses\.\*\.macAddress | string | 
action\_result\.data\.\*\.ipAddresses\.\*\.operationalStatus | string | 
action\_result\.data\.\*\.ipAddresses\.\*\.type | string | 
action\_result\.data\.\*\.isAadJoined | boolean | 
action\_result\.data\.\*\.lastExternalIpAddress | string |  `ip` 
action\_result\.data\.\*\.lastIpAddress | string |  `ip` 
action\_result\.data\.\*\.lastSeen | string | 
action\_result\.data\.\*\.managedBy | string | 
action\_result\.data\.\*\.managedByStatus | string | 
action\_result\.data\.\*\.onboardingStatus | string | 
action\_result\.data\.\*\.osArchitecture | string | 
action\_result\.data\.\*\.osBuild | numeric | 
action\_result\.data\.\*\.osPlatform | string | 
action\_result\.data\.\*\.osProcessor | string | 
action\_result\.data\.\*\.osVersion | string | 
action\_result\.data\.\*\.rbacGroupId | numeric | 
action\_result\.data\.\*\.rbacGroupName | string | 
action\_result\.data\.\*\.riskScore | string | 
action\_result\.data\.\*\.version | string | 
action\_result\.data\.\*\.vmMetadata | string | 
action\_result\.data\.\*\.vmMetadata\.cloudProvider | string | 
action\_result\.data\.\*\.vmMetadata\.resourceId | string | 
action\_result\.data\.\*\.vmMetadata\.subscriptionId | string | 
action\_result\.data\.\*\.vmMetadata\.vmId | string | 
action\_result\.summary\.total\_devices | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update device tag'
Add or remove a tag from a given device \(Maximum\: 200 characters\)

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | ID of the device | string |  `defender atp device id` 
**operation** |  required  | Determines whether the provided tag is added or removed | string | 
**tag** |  required  | Value of the tag to add or remove from the machine | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.device\_id | string |  `defender atp device id` 
action\_result\.parameter\.operation | string | 
action\_result\.parameter\.tag | string | 
action\_result\.data\.\*\.\@odata\.context | string | 
action\_result\.data\.\*\.\@odata\.context | string | 
action\_result\.data\.\*\.aadDeviceId | string | 
action\_result\.data\.\*\.agentVersion | string | 
action\_result\.data\.\*\.computerDnsName | string |  `domain` 
action\_result\.data\.\*\.defenderAvStatus | string | 
action\_result\.data\.\*\.defenderAvStatus | string | 
action\_result\.data\.\*\.deviceValue | string | 
action\_result\.data\.\*\.deviceValue | string | 
action\_result\.data\.\*\.exposureLevel | string | 
action\_result\.data\.\*\.firstSeen | string | 
action\_result\.data\.\*\.groupName | string | 
action\_result\.data\.\*\.healthStatus | string | 
action\_result\.data\.\*\.id | string |  `defender atp device id` 
action\_result\.data\.\*\.ipAddresses\.\*\.ipAddress | string | 
action\_result\.data\.\*\.ipAddresses\.\*\.ipAddress | string | 
action\_result\.data\.\*\.ipAddresses\.\*\.macAddress | string | 
action\_result\.data\.\*\.ipAddresses\.\*\.macAddress | string | 
action\_result\.data\.\*\.ipAddresses\.\*\.operationalStatus | string | 
action\_result\.data\.\*\.ipAddresses\.\*\.operationalStatus | string | 
action\_result\.data\.\*\.ipAddresses\.\*\.type | string | 
action\_result\.data\.\*\.ipAddresses\.\*\.type | string | 
action\_result\.data\.\*\.isAadJoined | boolean | 
action\_result\.data\.\*\.lastExternalIpAddress | string |  `ip` 
action\_result\.data\.\*\.lastIpAddress | string |  `ip` 
action\_result\.data\.\*\.lastSeen | string | 
action\_result\.data\.\*\.machineTags | string | 
action\_result\.data\.\*\.managedBy | string | 
action\_result\.data\.\*\.managedBy | string | 
action\_result\.data\.\*\.managedByStatus | string | 
action\_result\.data\.\*\.managedByStatus | string | 
action\_result\.data\.\*\.onboardingStatus | string | 
action\_result\.data\.\*\.onboardingStatus | string | 
action\_result\.data\.\*\.osArchitecture | string | 
action\_result\.data\.\*\.osArchitecture | string | 
action\_result\.data\.\*\.osBuild | numeric | 
action\_result\.data\.\*\.osPlatform | string | 
action\_result\.data\.\*\.osProcessor | string | 
action\_result\.data\.\*\.osVersion | string | 
action\_result\.data\.\*\.rbacGroupId | numeric | 
action\_result\.data\.\*\.rbacGroupName | string | 
action\_result\.data\.\*\.riskScore | string | 
action\_result\.data\.\*\.systemProductName | string | 
action\_result\.data\.\*\.version | string | 
action\_result\.data\.\*\.vmMetadata | string | 
action\_result\.data\.\*\.vmMetadata | string | 
action\_result\.summary\.operation | string | 
action\_result\.summary\.operation | string | 
action\_result\.summary\.tag | string | 
action\_result\.summary\.tag | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get discovered vulnerabilities'
Retrieve a collection of discovered vulnerabilities related to a given device ID

Type: **investigate**  
Read only: **True**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/get\-discovered\-vulnerabilities?view=o365\-worldwide" target="\_blank">Get discovered vulnerabilities API Documentation</a>\), rate limitations for this API are 50 calls per minute and 1500 calls per hour\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | ID of the device | string |  `defender atp device id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.device\_id | string |  `defender atp device id` 
action\_result\.data\.\*\.\@odata\.type | string | 
action\_result\.data\.\*\.\@odata\.type | string | 
action\_result\.data\.\*\.cvssV3 | numeric | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.exploitInKit | numeric | 
action\_result\.data\.\*\.exploitTypes | string | 
action\_result\.data\.\*\.exploitUris | string |  `url` 
action\_result\.data\.\*\.exploitVerified | numeric | 
action\_result\.data\.\*\.exposedMachines | numeric | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.publicExploit | numeric | 
action\_result\.data\.\*\.publishedOn | string | 
action\_result\.data\.\*\.severity | string | 
action\_result\.data\.\*\.updatedOn | string | 
action\_result\.summary\.total\_vulnerabilities | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'remove app restriction'
Enable execution of any application on the device

Type: **contain**  
Read only: **False**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/unrestrict\-code\-execution?view=o365\-worldwide" target="\_blank">Remove app restriction API Documentation</a>\), rate limitations for this API are 100 calls per minute and 1500 calls per hour\.<br>This action can take a while to complete execution\. The action retries at an interval of 5 seconds within a specified <b>timeout</b> to check if event execution is complete\. If not, the action would return the latest status of the event along with the event ID\.<br>The <b>get status</b> action can be used to fetch the latest status of the event with the event ID\.<br>The maximum timeout period for a status check is 1 minute\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | ID of the device | string |  `defender atp device id` 
**comment** |  required  | Comment | string | 
**timeout** |  optional  | Timeout in seconds \(Default\: 30\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.device\_id | string |  `defender atp device id` 
action\_result\.parameter\.timeout | numeric | 
action\_result\.data\.\*\.\@odata\.context | string |  `url` 
action\_result\.data\.\*\.cancellationComment | string | 
action\_result\.data\.\*\.cancellationDateTimeUtc | string | 
action\_result\.data\.\*\.cancellationRequestor | string | 
action\_result\.data\.\*\.computerDnsName | string | 
action\_result\.data\.\*\.creationDateTimeUtc | string | 
action\_result\.data\.\*\.error | string | 
action\_result\.data\.\*\.errorHResult | numeric | 
action\_result\.data\.\*\.externalId | string | 
action\_result\.data\.\*\.id | string |  `defender atp event id` 
action\_result\.data\.\*\.lastUpdateDateTimeUtc | string | 
action\_result\.data\.\*\.machineId | string |  `defender atp device id` 
action\_result\.data\.\*\.relatedFileInfo | string | 
action\_result\.data\.\*\.requestSource | string | 
action\_result\.data\.\*\.requestor | string | 
action\_result\.data\.\*\.requestorComment | string | 
action\_result\.data\.\*\.scope | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.troubleshootInfo | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.event\_id | string |  `defender atp event id` 
action\_result\.summary\.remove\_app\_restriction\_status | string | 
action\_result\.summary\.restriction\_status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get exposure score'
Retrieve the organizational exposure score

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.\@odata\.context | string |  `url` 
action\_result\.data\.\*\.rbacGroupId | string | 
action\_result\.data\.\*\.rbacGroupName | string | 
action\_result\.data\.\*\.score | numeric | 
action\_result\.data\.\*\.time | string | 
action\_result\.summary\.exposure\_score | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get secure score'
Retrieve your Microsoft Secure Score for devices

Type: **investigate**  
Read only: **True**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/get\-device\-secure\-score?view=o365\-worldwide" target="\_blank">Get device secure score API Documentation</a>\), a higher Microsoft Secure Score for devices means your endpoints are more resilient from cybersecurity threat attacks\.

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.\@odata\.context | string |  `url` 
action\_result\.data\.\*\.rbacGroupId | string | 
action\_result\.data\.\*\.rbacGroupName | string | 
action\_result\.data\.\*\.score | numeric | 
action\_result\.data\.\*\.time | string | 
action\_result\.summary\.secure\_score | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get file'
Download a file from a device using live response

Type: **generic**  
Read only: **False**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/run\-live\-response?view=o365\-worldwide" target="\_blank">Run live response commands on a device API Documentation</a>\), the user can collect file from a device in the vault, rate limitations for this API are 10 calls per minute\.<br>The action tries to get the file using file\_path along with the device\_id\. This action can take a while to complete the execution\. The action retries at an interval of 5 seconds within a specified timeout to check if event execution is completed\. If not, the action would return the latest status of the event along with the event ID\. The get status action can be used to fetch the latest status of the event with the event ID\. If the status is 'Succeeded', the event ID can be used in the same action to get the file\. If all the parameters are given, the action gives higher priority to the event ID parameter\.<br><br><b>Notes\:</b><ul><li>Live response actions cannot be queued up and can only be executed one at a time\.</li><li>If the machine that you are trying to run this action is in an RBAC device group that does not have an automated remediation level assigned to it, you'll need to at least enable the minimum Remediation Level for a given Device Group\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**event\_id** |  optional  | ID of the event | string |  `defender atp event id` 
**device\_id** |  optional  | ID of the device | string |  `defender atp device id` 
**file\_path** |  optional  | Path of the file to download from device | string |  `file path` 
**comment** |  optional  | Comment | string | 
**timeout** |  optional  | Timeout in seconds \(Default\: 300\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.device\_id | string |  `defender atp device id` 
action\_result\.parameter\.event\_id | string |  `defender atp event id` 
action\_result\.parameter\.file\_path | string |  `file path` 
action\_result\.parameter\.timeout | numeric | 
action\_result\.data\.\*\.\@odata\.context | string |  `url` 
action\_result\.data\.\*\.cancellationComment | string | 
action\_result\.data\.\*\.cancellationDateTimeUtc | string | 
action\_result\.data\.\*\.cancellationRequestor | string | 
action\_result\.data\.\*\.commands\.\*\.command\.params\.\*\.key | string | 
action\_result\.data\.\*\.commands\.\*\.command\.params\.\*\.value | string |  `file path` 
action\_result\.data\.\*\.commands\.\*\.command\.type | string | 
action\_result\.data\.\*\.commands\.\*\.commandStatus | string | 
action\_result\.data\.\*\.commands\.\*\.endTime | string | 
action\_result\.data\.\*\.commands\.\*\.index | numeric | 
action\_result\.data\.\*\.commands\.\*\.startTime | string | 
action\_result\.data\.\*\.computerDnsName | string | 
action\_result\.data\.\*\.creationDateTimeUtc | string | 
action\_result\.data\.\*\.errorHResult | numeric | 
action\_result\.data\.\*\.externalId | string | 
action\_result\.data\.\*\.id | string |  `defender atp event id` 
action\_result\.data\.\*\.lastUpdateDateTimeUtc | string | 
action\_result\.data\.\*\.machineId | string |  `defender atp device id` 
action\_result\.data\.\*\.relatedFileInfo | string | 
action\_result\.data\.\*\.requestSource | string | 
action\_result\.data\.\*\.requestor | string | 
action\_result\.data\.\*\.requestorComment | string | 
action\_result\.data\.\*\.scope | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.troubleshootInfo | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.event\_id | string |  `defender atp event id` 
action\_result\.summary\.event\_id\_status | string | 
action\_result\.summary\.file\_status | string | 
action\_result\.summary\.live\_response\_result | string | 
action\_result\.summary\.vault\_id | string |  `vault id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'put file'
Put a file from the library to a device using live response

Type: **generic**  
Read only: **False**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/run\-live\-response?view=o365\-worldwide" target="\_blank">Run live response commands on a device API Documentation</a>\), the user can put a file from the library to the device, rate limitations for this API are 10 calls per minute\.<br>This action can take a while to complete execution\. The action retries at an interval of 5 seconds within a specified <b>timeout</b> to check if event execution is complete\. If not, the action would return the latest status of the event along with the event ID\.<br>The <b>get status</b> action can be used to fetch the latest status of the event with the event ID\.<br><b>Notes\:</b><ul><li>Live response actions cannot be queued up and can only be executed one at a time\.</li><li>If the machine that you are trying to run this action is in an RBAC device group that does not have an automated remediation level assigned to it, you'll need to at least enable the minimum Remediation Level for a given Device Group\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | ID of the device | string |  `defender atp device id` 
**file\_name** |  required  | Name of the file | string |  `file name` 
**comment** |  required  | Comment | string | 
**timeout** |  optional  | Timeout in seconds \(Default\: 300\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.device\_id | string |  `defender atp device id` 
action\_result\.parameter\.file\_name | string |  `file name` 
action\_result\.parameter\.timeout | numeric | 
action\_result\.data\.\*\.\@odata\.context | string |  `url` 
action\_result\.data\.\*\.cancellationComment | string | 
action\_result\.data\.\*\.cancellationDateTimeUtc | string | 
action\_result\.data\.\*\.cancellationRequestor | string | 
action\_result\.data\.\*\.commands\.\*\.command\.params\.\*\.key | string | 
action\_result\.data\.\*\.commands\.\*\.command\.params\.\*\.value | string |  `file name` 
action\_result\.data\.\*\.commands\.\*\.command\.type | string | 
action\_result\.data\.\*\.commands\.\*\.commandStatus | string | 
action\_result\.data\.\*\.commands\.\*\.endTime | string | 
action\_result\.data\.\*\.commands\.\*\.index | numeric | 
action\_result\.data\.\*\.commands\.\*\.startTime | string | 
action\_result\.data\.\*\.computerDnsName | string | 
action\_result\.data\.\*\.creationDateTimeUtc | string | 
action\_result\.data\.\*\.errorHResult | numeric | 
action\_result\.data\.\*\.externalId | string | 
action\_result\.data\.\*\.id | string |  `defender atp event id` 
action\_result\.data\.\*\.lastUpdateDateTimeUtc | string | 
action\_result\.data\.\*\.machineId | string |  `defender atp device id` 
action\_result\.data\.\*\.relatedFileInfo | string | 
action\_result\.data\.\*\.requestSource | string | 
action\_result\.data\.\*\.requestor | string | 
action\_result\.data\.\*\.requestorComment | string | 
action\_result\.data\.\*\.scope | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.troubleshootInfo | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary\.event\_id | string |  `defender atp event id` 
action\_result\.summary\.put\_file\_status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'run script'
Run a script from the library on a device using live response

Type: **generic**  
Read only: **False**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/run\-live\-response?view=o365\-worldwide" target="\_blank">Run live response commands on a device API Documentation</a>\), the user can run a script from the library on a device\. The script\_args parameter is passed to your script, rate limitations for this API are 10 calls per minute\.<br>The action tries to execute the script using script\_name along with the device\_id\. This action can take a while to complete the execution\. The action retries at an interval of 5 seconds within a specified timeout to check if event execution is completed\. If not, the action would return the latest status of the event along with the event ID\. The get status action can be used to fetch the latest status of the event with the event ID\. If the status is 'Succeded', the event ID can be used in the same action to get the script output\. If all the parameters are given, the action gives higher priority to the event ID parameter\.<br><br><b>Notes\:</b><ul><li>The maximum timeout period for the script execution is 10 minutes\.</li><li>Live response actions cannot be queued up and can only be executed one at a time\.</li><li>If the machine that you are trying to run this action is in an RBAC device group that does not have an automated remediation level assigned to it, you'll need to at least enable the minimum Remediation Level for a given Device Group\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**event\_id** |  optional  | ID of the event | string |  `defender atp event id` 
**device\_id** |  optional  | ID of the device | string |  `defender atp device id` 
**script\_name** |  optional  | Name of the script file to execute on the device | string |  `file name` 
**script\_args** |  optional  | Arguments of the script file | string | 
**comment** |  optional  | Comment | string | 
**timeout** |  optional  | Timeout in seconds \(Default\: 300\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.device\_id | string |  `defender atp device id` 
action\_result\.parameter\.event\_id | string |  `defender atp event id` 
action\_result\.parameter\.script\_args | string | 
action\_result\.parameter\.script\_name | string |  `file name` 
action\_result\.parameter\.timeout | numeric | 
action\_result\.data\.\*\.exit\_code | numeric | 
action\_result\.data\.\*\.script\_errors | string | 
action\_result\.data\.\*\.script\_name | string | 
action\_result\.data\.\*\.script\_output | string | 
action\_result\.summary\.event\_id | string |  `defender atp event id` 
action\_result\.summary\.event\_id\_status | string | 
action\_result\.summary\.live\_response\_result | string | 
action\_result\.summary\.script\_status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get missing kbs'
Retrieve missing KBs \(security updates\) by given device ID

Type: **investigate**  
Read only: **True**

Based on the link \(<a href="https\://docs\.microsoft\.com/en\-us/microsoft\-365/security/defender\-endpoint/get\-missing\-kbs\-machine?view=o365\-worldwide" target="\_blank">Get missing KBs API Documentation</a>\), the user can retrieve a collection of missing security updated related to a given device ID\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | ID of the device | string |  `defender atp device id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.device\_id | string |  `defender atp device id` 
action\_result\.data\.\*\.cveAddressed | numeric | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.machineMissedOn | numeric | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.osBuild | numeric | 
action\_result\.data\.\*\.productsNames | string | 
action\_result\.data\.\*\.url | string |  `url` 
action\_result\.summary\.total\_kbs | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 