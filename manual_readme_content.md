[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2019-2024 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Defender for Endpoint Instance Minimum Version Compatibility

-   With this major version 2.0.0 of the Microsoft Defender for Endpoint app on Splunk SOAR, we declare support
    for (on and above) the cloud 'November-December 2019' GA release for the Defender for Endpoint instances. This app
    has been tested and certified on the mentioned GA release of the Defender for Endpoint and its APIs.

## Playbook Backward Compatibility

-   The existing action parameters have been modified in the actions given below. Hence, it is
    requested to the end-user to please update their existing playbooks by re-inserting | modifying
    | deleting the corresponding action blocks, or by providing appropriate values to these action
    parameters to ensure the correct functioning of the playbooks created on the earlier versions of
    the app.

      

    -   List Devices - The 'IP' option has been removed from the value list of the \[input_type\]
        action parameter in the app version 3.0.0 because there is no specific API currently
        available to support the filtering of devices based on the IP in the Defender for Endpoint.
    -   List Devices - The new \[query\] parameter has been added to support the additional OData V4
        filters.

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Defender for Endpoint server. Below are the
default ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |

## Pagination Not Supported

-   Based on the base URL link ( [Microsoft Defender for Endpoint API
    Documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/exposed-apis-list)
    ), the pagination is not supported by the Defender for Endpoint APIs. Hence, this app does not implement
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

## Explanation of Asset Configuration Parameters for On Poll

-   Max Alerts for Polling - During each polling cycle, the specified number of alerts is retrieved for scheduled or interval polling (Default: 1000). Each alert is ingested as a container. This parameter determines the maximum number of alerts that can be fetched in a single poll cycle.
-   Start Time - This parameter is used to filter alerts based on their last updated time. If no value is provided, the default behavior is a week.<br>
**Note: The start time filters alerts based on their lastUpdateTime property.**
-   Filter - Allows additional filtering to be applied to alert properties (such as severity or status). This is useful for targeting specific types of alerts during polling.

## Explanation of On Poll Behavior

-   Start Time Parameter - The `start_time` parameter directly correlates with the lastUpdateTime property of the alerts, ensuring that only alerts updated after this time are included in the ingestion process.
-   Max Alerts Parameter - The `max_alerts_per_poll` setting works only with scheduled or interval polling, controlling how many alerts are ingested per cycle. For instance, if this value is set to 100, the system will ingest up to 100 distinct alerts, applying the provided filters and start time.
-   Example - If you configure the maximum alerts parameter to 100, the on_poll function will retrieve up to 100 alerts, considering any filter and start time provided. The filtering ensures only relevant alerts based on the time and other criteria are ingested during the polling process.

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



## Configure the Microsoft Defender for Endpoint SOAR app's asset

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
    configured asset for the Defender for Endpoint app on SOAR. Copy the URL mentioned in the 'POST incoming for
    Microsoft Defender for Endpoint to this location' field. Add a suffix '/result' to the URL copied in the
    previous step. The resulting URL looks like the one mentioned below.

      

                    https://<soar_host>/rest/handler/microsoftdefenderforendpoint_<appid>/<asset_name>/result
                  

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
-   Log in using the same Microsoft account that was used to configure the Microsoft Defender for Endpoint
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
    the Defender for Endpoint instance.

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

    -   Configure the Microsoft Defender for Endpoint app's asset with appropriate values for \[tenant_id\],
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
            API calls to the Defender for Endpoint instance.

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
            actions execution flow to authorize their API calls to the Defender for Endpoint instance.

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
    'POST incoming for Microsoft Defender for Endpoint to this location' when the Defender for Endpoint Splunk SOAR app
    asset is configured e.g.
    https://\<splunk_soar_host>/rest/handler/microsoftdefenderforendpoint\_\<appid>/\<asset_name>/result
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
