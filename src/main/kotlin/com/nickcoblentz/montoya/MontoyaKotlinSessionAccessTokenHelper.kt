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
import burp.api.montoya.ui.settings.SettingsPanelWithData
import java.awt.Component
import java.util.Optional
import java.util.regex.Pattern
import javax.swing.JMenuItem
import kotlin.getValue
import kotlin.properties.ReadOnlyProperty


class MontoyaKotlinSessionAccessTokenHelper : BurpExtension, SessionHandlingAction, ContextMenuItemsProvider, HttpHandler {

    private lateinit var messageEditorRequestResponse: Optional<MessageEditorHttpRequestResponse>
    private lateinit var selectedRequestResponses: MutableList<HttpRequestResponse>
    private lateinit var montoyaApi: MontoyaApi
    private var accessToken = ""
    private lateinit var logger: MontoyaLogger

    private val testJMenu = JMenuItem("Test It")

    private lateinit var myExtensionSettings : MyExtensionSettings

    companion object {
        const val PLUGIN_NAME: String = "Session Handling: Access Token Helper"

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

        myExtensionSettings = MyExtensionSettings()

        api.userInterface().registerSettingsPanel(myExtensionSettings?.settingsPanel)

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
            if(myExtensionSettings.headerName1Setting.isNotBlank()) {
                logger.debugLog("Access Token and Header1 Not Empty, adding header: ${myExtensionSettings.headerName1Setting}: ${previewHeaderValue()}")
                newRequest = if (newRequest.hasHeader(myExtensionSettings.headerName1Setting))
                    newRequest.withUpdatedHeader(myExtensionSettings.headerName1Setting, previewHeaderValue())
                else
                    newRequest.withAddedHeader(myExtensionSettings.headerName1Setting, previewHeaderValue())
            }
            else
                logger.debugLog("Skipping ${myExtensionSettings.headerName1Setting} header, empty")

            if(myExtensionSettings.headerName2Setting.isNotBlank()) {
                logger.debugLog("Access Token and Header2 Not Empty, adding header: ${myExtensionSettings.headerName2Setting}: ${previewHeaderValue()}")
                newRequest = if (newRequest.hasHeader(myExtensionSettings.headerName2Setting))
                    newRequest.withUpdatedHeader(myExtensionSettings.headerName2Setting, previewHeaderValue(true))
                else
                    newRequest.withAddedHeader(myExtensionSettings.headerName2Setting, previewHeaderValue(true))
            }
            else
                logger.debugLog("Skipping ${myExtensionSettings.headerName2Setting} header, empty")
        }
        return newRequest
    }

    fun urlShouldBeIgnored(request: HttpRequest) : Boolean {
        return myExtensionSettings.shouldIgnoreEndpointsSetting
                && myExtensionSettings.ignoreEndpointsSetting.isNotBlank()
                && myExtensionSettings.ignoreEndpointsSetting.toRegex().containsMatchIn(request.url())
    }

    fun updateAccessTokenIfFound(responseString: String)
    {
        //Logger.debugLog("response string:\n$responseString")
        val pattern = Pattern.compile(myExtensionSettings.accessTokenPatternSetting, Pattern.CASE_INSENSITIVE)
        val matcher = pattern.matcher(responseString)
        while (matcher.find() && matcher.groupCount() > 0) {
            accessToken = matcher.group(1)
            logger.debugLog("Found Access Token: $accessToken")
        }
    }

    private fun previewHeaderValue(secondHeader : Boolean = false) : String {
        val headerBuilder = StringBuilder()
        if(secondHeader) {
            headerBuilder.append(myExtensionSettings.headerValuePrefix2Setting)
            if(accessToken.isEmpty())
                headerBuilder.append("ACCESS TOKEN HERE")
            else
                headerBuilder.append(accessToken)
            headerBuilder.append(myExtensionSettings.headerValueSuffix2Setting)
        }
        else {
            headerBuilder.append(myExtensionSettings.headerValuePrefix1Setting)
            if(accessToken.isEmpty())
                headerBuilder.append("ACCESS TOKEN HERE")
            else
                headerBuilder.append(accessToken)
            headerBuilder.append(myExtensionSettings.headerValueSuffix1Setting)
        }

        return headerBuilder.toString()
    }

    override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent?): RequestToBeSentAction {
        return RequestToBeSentAction.continueWith(requestToBeSent)
    }

    override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived?): ResponseReceivedAction {
        if(myExtensionSettings.passiveSetting)
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

class SettingsDelegateManager(private var settingsPanelBuilder : SettingsPanelBuilder) {

    var settingsPanel : SettingsPanelWithData? = null

    fun stringSetting(name: String, defaultValue: String): ReadOnlyProperty<Any?, String> {
        settingsPanelBuilder.withSetting(SettingsPanelSetting.stringSetting(name, defaultValue))

        // This delegate will call the provider to get the panel only when the property is accessed.
        return ReadOnlyProperty { _, _ -> settingsPanel?.getString(name) ?: "" }
    }

    /**
     * Creates and registers a Boolean setting delegate.
     */
    fun booleanSetting(name: String, defaultValue: Boolean): ReadOnlyProperty<Any?, Boolean> {
        settingsPanelBuilder.withSetting(SettingsPanelSetting.booleanSetting(name, defaultValue))
        return ReadOnlyProperty { _, _ -> settingsPanel?.getBoolean(name) ?: false}
    }

    fun finished() {
        settingsPanel = settingsPanelBuilder.build()
    }
}


class MyExtensionSettings {
    private val settingsManager : SettingsDelegateManager
    val settingsPanel : SettingsPanelWithData

    init {
        val settingsPanelBuilder = SettingsPanelBuilder.settingsPanel()
            .withPersistence(SettingsPanelPersistence.PROJECT_SETTINGS)
            .withTitle("Session Token Helper")
            .withDescription("Configure the session handling settings.")
            .withKeywords("Session", "JWT", "Authorization", "Token", "Macro")
            //.withSettings(*settingsManager.settingDefinitions.toTypedArray())
        settingsManager = SettingsDelegateManager(settingsPanelBuilder)
        settingsManager.finished()
        settingsPanel = settingsManager.settingsPanel!!
    }


    val accessTokenPatternSetting: String by settingsManager.stringSetting("Access Token RegEx Pattern", "\"access_token\" *: *\"([^\"]+)\"")
    val headerName1Setting: String by settingsManager.stringSetting("Header Name 1", "Authorization")
    val headerValuePrefix1Setting: String by settingsManager.stringSetting("Header Value Prefix 1", "Bearer ")
    val headerValueSuffix1Setting: String by settingsManager.stringSetting("Header Value Suffix 1", "")
    val headerName2Setting: String by settingsManager.stringSetting("Header Name 2", "")
    val headerValuePrefix2Setting: String by settingsManager.stringSetting("Header Value Prefix 2", "")
    val headerValueSuffix2Setting: String by settingsManager.stringSetting("Header Value Suffix 2", "")
    val ignoreEndpointsSetting: String by settingsManager.stringSetting("Regex of URLs to Ignore when applying the token", "")

    val passiveSetting: Boolean by settingsManager.booleanSetting("Use Passively For All Requests?", false)
    val shouldIgnoreEndpointsSetting: Boolean by settingsManager.booleanSetting("Should Ignore Endpoints?", false)
}

//
//class MyExtensionSettings() {
//    private val _accessTokenPatternSetting by lazy {
//        SettingsPanelSetting.stringSetting(
//            SettingsName.ACCESS_TOKEN_PATTERN.value,
//            "\"access_token\" *: *\"([^\"]+)\""
//        )
//    }
//
//    val accessTokenPatternSetting : String
//        get() = settingsPanel.getString(SettingsName.ACCESS_TOKEN_PATTERN.value)
//
//
//    private val _headerName1Setting by lazy {
//        SettingsPanelSetting.stringSetting(
//            SettingsName.HEADER_NAME_1.value,
//            "Authorization"
//        )
//    }
//
//    val headerName1Setting : String
//        get() = myExtesionSettions.headerName1Setting
//
//    private val _headerValuePrefix1Setting by lazy {
//        SettingsPanelSetting.stringSetting(
//            SettingsName.HEADER_VALUE_PREFIX_1.value,
//            "Bearer "
//        )
//    }
//
//    val headerValuePrefix1Setting : String
//        get() = settingsPanel.getString(SettingsName.HEADER_VALUE_PREFIX_1.value)
//
//    private val _headerValueSuffix1Setting by lazy {
//        SettingsPanelSetting.stringSetting(
//            SettingsName.HEADER_VALUE_SUFFIX_1.value,
//            ""
//        )
//    }
//
//    val headerValueSuffix1Setting : String
//        get() = settingsPanel.getString(SettingsName.HEADER_VALUE_SUFFIX_1.value)
//
//    private val _headerName2Setting by lazy {
//        SettingsPanelSetting.stringSetting(
//            SettingsName.HEADER_NAME_2.value,
//            "Authorization"
//        )
//    }
//
//    val headerName2Setting : String
//        get() = myExtesionSettions.headerName2Setting
//
//    private val _headerValuePrefix2Setting by lazy {
//        SettingsPanelSetting.stringSetting(
//            SettingsName.HEADER_VALUE_PREFIX_2.value,
//            "Bearer "
//        )
//    }
//
//    val headerValuePrefix2Setting : String
//        get() = settingsPanel.getString(SettingsName.HEADER_VALUE_PREFIX_2.value)
//
//    private val _headerValueSuffix2Setting by lazy {
//        SettingsPanelSetting.stringSetting(
//            SettingsName.HEADER_VALUE_SUFFIX_2.value,
//            ""
//        )
//    }
//
//    val headerValueSuffix2Setting : String
//        get() = settingsPanel.getString(SettingsName.HEADER_VALUE_SUFFIX_2.value)
//
//    private val _passiveSetting  by lazy {
//        SettingsPanelSetting.booleanSetting(
//            SettingsName.PASSIVE_NAME.value,
//            false
//        )
//    }
//
//    val passiveSetting : Boolean
//        get() = settingsPanel.getBoolean(SettingsName.PASSIVE_NAME.value)
//
//    private val _ignoreEndpointsSetting by lazy {
//        SettingsPanelSetting.stringSetting(
//            SettingsName.IGNORE_ENDPOINTS.value,
//            ""
//        )
//    }
//
//    val ignoreEndpointsSetting : String
//        get() = settingsPanel.getString(SettingsName.IGNORE_ENDPOINTS.value)
//
//    private val _shouldIgnoreEndpointsSetting by lazy {
//        SettingsPanelSetting.booleanSetting(
//            SettingsName.SHOULD_IGNORE_ENDPOINTS.value,
//            false
//        )
//    }
//
//    val shouldIgnoreEndpointsSetting : Boolean
//        get() = settingsPanel.getBoolean(SettingsName.SHOULD_IGNORE_ENDPOINTS.value)
//
//    val settingsPanel by lazy {
//        SettingsPanelBuilder.settingsPanel()
//            .withPersistence(SettingsPanelPersistence.PROJECT_SETTINGS)
//            .withTitle("Session Token Helper")
//            .withDescription("Configure the session handling settings.")
//            .withKeywords("Session", "JWT", "Authorization", "Token", "Macro")
//            .withSettings(
//                _accessTokenPatternSetting,
//                _headerName1Setting,
//                _headerValuePrefix1Setting,
//                _headerValueSuffix1Setting,
//                _headerName2Setting,
//                _headerValuePrefix2Setting,
//                _headerValueSuffix2Setting,
//                _passiveSetting,
//                _ignoreEndpointsSetting,
//                _shouldIgnoreEndpointsSetting
//            )
//            .build()
//
//
//    }
//
//
//}