package com.nickcoblentz.montoya
import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.handler.*
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.sessions.ActionResult
import burp.api.montoya.http.sessions.SessionHandlingAction
import burp.api.montoya.http.sessions.SessionHandlingActionData
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent
import burp.api.montoya.ui.settings.SettingsPanelBuilder
import burp.api.montoya.ui.settings.SettingsPanelPersistence
import burp.api.montoya.ui.settings.SettingsPanelSetting
import java.awt.Component
import java.util.Optional
import java.util.regex.Pattern
import javax.swing.JMenuItem


enum class SettingsName (val value: String) {
    HEADER_NAME_1("Header Name 1"),
    HEADER_VALUE_PREFIX_1("Header Value Prefix 1"),
    HEADER_VALUE_SUFFIX_1("Header Value Suffix 1"),
    HEADER_NAME_2("Header Name 2"),
    HEADER_VALUE_PREFIX_2("Header Value Prefix 2"),
    HEADER_VALUE_SUFFIX_2("Header Value Suffix 2"),
    ACCESS_TOKEN_PATTERN("Access Token RegEx Pattern"),
    PASSIVE_NAME("Use Passively For All Requests?"),
    IGNORE_ENDPOINTS("Regex of URLs to Ignore when applying the token"),
    SHOULD_IGNORE_ENDPOINTS("Should Ignore Endpoints?")
}

class MontoyaKotlinSessionAccessTokenHelper : BurpExtension, SessionHandlingAction, ContextMenuItemsProvider, HttpHandler {

    private lateinit var messageEditorRequestResponse: Optional<MessageEditorHttpRequestResponse>
    private lateinit var selectedRequestResponses: MutableList<HttpRequestResponse>
    private lateinit var montoyaApi: MontoyaApi
    private var accessToken = ""
    private lateinit var logger: MontoyaLogger

    private val testJMenu = JMenuItem("Test It")


    companion object {
        const val PLUGIN_NAME: String = "Session Handling: Access Token Helper"

    }

    private val accessTokenPatternSetting by lazy  {
        SettingsPanelSetting.stringSetting(
        SettingsName.ACCESS_TOKEN_PATTERN.value,
        "\"access_token\" *: *\"([^\"]+)\""
        )
    }

    private val headerName1Setting by lazy {
        SettingsPanelSetting.stringSetting(
            SettingsName.HEADER_NAME_1.value,
            "Authorization"
        )
    }

    private val headerValuePrefix1Setting by lazy {
        SettingsPanelSetting.stringSetting(
            SettingsName.HEADER_VALUE_PREFIX_1.value,
            "Bearer "
        )
    }
    private val headerValueSuffix1Setting by lazy {
        SettingsPanelSetting.stringSetting(
            SettingsName.HEADER_VALUE_SUFFIX_1.value,
            ""
        )
    }

    private val headerName2Setting by lazy {
        SettingsPanelSetting.stringSetting(
            SettingsName.HEADER_NAME_2.value,
            "Authorization"
        )
    }

    private val headerValuePrefix2Setting by lazy {
        SettingsPanelSetting.stringSetting(
            SettingsName.HEADER_VALUE_PREFIX_2.value,
            "Bearer "
        )
    }

    private val headerValueSuffix2Setting by lazy {
        SettingsPanelSetting.stringSetting(
            SettingsName.HEADER_VALUE_SUFFIX_2.value,
            ""
        )
    }

    private val passiveSetting  by lazy {
        SettingsPanelSetting.booleanSetting(
            SettingsName.PASSIVE_NAME.value,
            false
        )
    }

    private val ignoreEndpointsSetting by lazy {
        SettingsPanelSetting.stringSetting(
            SettingsName.IGNORE_ENDPOINTS.value,
            ""
        )
    }

    private val shouldIgnoreEndpointsSetting by lazy {
        SettingsPanelSetting.booleanSetting(
            SettingsName.SHOULD_IGNORE_ENDPOINTS.value,
            false
        )
    }

    private val settingsPanel by lazy {
        SettingsPanelBuilder.settingsPanel()
            .withPersistence(SettingsPanelPersistence.PROJECT_SETTINGS)
            .withTitle("Session Token Helper")
            .withDescription("Configure the session handling settings.")
            .withKeywords("Session", "JWT", "Authorization", "Token", "Macro")
            .withSettings(
                accessTokenPatternSetting,
                headerName1Setting,
                headerValuePrefix1Setting,
                headerValueSuffix1Setting,
                headerName2Setting,
                headerValuePrefix2Setting,
                headerValueSuffix2Setting,
                passiveSetting,
                ignoreEndpointsSetting,
                shouldIgnoreEndpointsSetting
            )
            .build()
    }

    override fun initialize(api: MontoyaApi?) {
        if(api==null)
        {
            return
        }
        montoyaApi=api

        logger = MontoyaLogger(api, LogLevel.DEBUG)
        logger.debugLog( "Plugin Starting...")
        api.extension().setName(PLUGIN_NAME)
        api.http().registerSessionHandlingAction(this)

        api.userInterface().registerSettingsPanel(settingsPanel)

        api.userInterface().registerContextMenuItemsProvider(this)

        api.http().registerHttpHandler(this)

        testJMenu.addActionListener {actionEvent ->
            val requests = mutableListOf<HttpRequest>()
            messageEditorRequestResponse.ifPresent { requestResponse ->
                requests.add(requestResponse.requestResponse().request())
            }
            if(selectedRequestResponses.isNotEmpty()) {
                requests.addAll(selectedRequestResponses.map { it.request() })
            }

            requests.forEach { request ->
                montoyaApi.logging().logToOutput("=================${request.url()}=================")
                montoyaApi.logging().logToOutput(updateRequestWithAccessToken(request).toString())
                montoyaApi.logging().logToOutput("--------------------------------------------------")
            }


        }
        logger.debugLog( "Finished")


    }

    override fun name(): String {
        return PLUGIN_NAME
    }

    override fun performAction(actionData: SessionHandlingActionData): ActionResult {
        logger.debugLog(this.javaClass.name, "=======================\nperformAction")
        var request = actionData.request()

        logger.debugLog("---------------------------\nStage 1: Checking for Macros")
        if(actionData.macroRequestResponses().isNotEmpty()) {
            logger.debugLog("Found Macro Request/Response")
            for (httpReqRes in actionData.macroRequestResponses()) {
                if(httpReqRes.hasResponse())
                    updateAccessTokenIfFound(httpReqRes.response().toString())
            }
        }
        else
            logger.debugLog("No macro found")

        logger.debugLog("------------------------\nStage 2: Session Handling")

        request = updateRequestWithAccessToken(request)

        logger.debugLog("Done, returning")
        return ActionResult.actionResult(request, actionData.annotations())
    }

    fun updateRequestWithAccessToken(request: HttpRequest) : HttpRequest {
        var newRequest = request
        logger.debugLog("updating with access token: $accessToken")
        if (accessToken.isNotEmpty() && !urlShouldBeIgnored(newRequest)) {
            logger.debugLog("Access token non-empty: ${accessToken}, valid URL (not ignore url): ${newRequest.url()}")
            if(settingsPanel.getString(SettingsName.HEADER_NAME_1.value).isNotBlank()) {
                logger.debugLog("Access Token and Header1 Not Empty, adding header: ${settingsPanel.getString(SettingsName.HEADER_NAME_1.value)}: ${previewHeaderValue()}")
                newRequest = if (newRequest.hasHeader(settingsPanel.getString(SettingsName.HEADER_NAME_1.value)))
                    newRequest.withUpdatedHeader(settingsPanel.getString(SettingsName.HEADER_NAME_1.value), previewHeaderValue())
                else
                    newRequest.withAddedHeader(settingsPanel.getString(SettingsName.HEADER_NAME_1.value), previewHeaderValue())
            }
            else
                logger.debugLog("Skipping ${settingsPanel.getString(SettingsName.HEADER_NAME_1.value)} header, empty")

            if(settingsPanel.getString(SettingsName.HEADER_NAME_2.value).isNotBlank()) {
                logger.debugLog("Access Token and Header2 Not Empty, adding header: ${settingsPanel.getString(SettingsName.HEADER_NAME_2.value)}: ${previewHeaderValue()}")
                newRequest = if (newRequest.hasHeader(settingsPanel.getString(SettingsName.HEADER_NAME_2.value)))
                    newRequest.withUpdatedHeader(settingsPanel.getString(SettingsName.HEADER_NAME_2.value), previewHeaderValue(true))
                else
                    newRequest.withAddedHeader(settingsPanel.getString(SettingsName.HEADER_NAME_2.value), previewHeaderValue(true))
            }
            else
                logger.debugLog("Skipping ${settingsPanel.getString(SettingsName.HEADER_NAME_2.value)} header, empty")
        }
        return newRequest
    }

    fun urlShouldBeIgnored(request: HttpRequest) : Boolean {
        return settingsPanel.getBoolean(SettingsName.SHOULD_IGNORE_ENDPOINTS.value)
                && settingsPanel.getString(SettingsName.IGNORE_ENDPOINTS.value).isNotBlank()
                && settingsPanel.getString(SettingsName.IGNORE_ENDPOINTS.value).toRegex().containsMatchIn(request.url())
    }

    fun updateAccessTokenIfFound(responseString: String)
    {
        //Logger.debugLog("response string:\n$responseString")
        val pattern = Pattern.compile(settingsPanel.getString(SettingsName.ACCESS_TOKEN_PATTERN.value), Pattern.CASE_INSENSITIVE)
        val matcher = pattern.matcher(responseString)
        while (matcher.find() && matcher.groupCount() > 0) {
            accessToken = matcher.group(1)
            logger.debugLog("Found Access Token: $accessToken")
        }
    }

    private fun previewHeaderValue(secondHeader : Boolean = false) : String {
        val headerBuilder = StringBuilder()
        if(secondHeader) {
            headerBuilder.append(settingsPanel.getString(SettingsName.HEADER_VALUE_PREFIX_2.value))
            if(accessToken.isEmpty())
                headerBuilder.append("ACCESS TOKEN HERE")
            else
                headerBuilder.append(accessToken)
            headerBuilder.append(settingsPanel.getString(SettingsName.HEADER_VALUE_SUFFIX_2.value))
        }
        else {
            headerBuilder.append(settingsPanel.getString(SettingsName.HEADER_VALUE_PREFIX_1.value))
            if(accessToken.isEmpty())
                headerBuilder.append("ACCESS TOKEN HERE")
            else
                headerBuilder.append(accessToken)
            headerBuilder.append(settingsPanel.getString(SettingsName.HEADER_VALUE_SUFFIX_1.value))
        }

        return headerBuilder.toString()
    }

    override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent?): RequestToBeSentAction {
        return RequestToBeSentAction.continueWith(requestToBeSent)
    }

    override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived?): ResponseReceivedAction {
        if(settingsPanel.getBoolean(SettingsName.PASSIVE_NAME.value))
            responseReceived?.let {
                updateAccessTokenIfFound(it.toString())
            }
        return ResponseReceivedAction.continueWith(responseReceived)
    }

    override fun provideMenuItems(event: ContextMenuEvent?): List<Component?>? {
        event?.let {
            if(it.selectedRequestResponses().isNotEmpty() || !it.messageEditorRequestResponse().isEmpty) {
                selectedRequestResponses = it.selectedRequestResponses()
                messageEditorRequestResponse = it.messageEditorRequestResponse()
                return listOf(testJMenu)
            }
        }
        return super.provideMenuItems(event)
    }

    override fun provideMenuItems(event: WebSocketContextMenuEvent?): List<Component?>? {
        return super.provideMenuItems(event)
    }

    override fun provideMenuItems(event: AuditIssueContextMenuEvent?): List<Component?>? {
        return super.provideMenuItems(event)
    }
}