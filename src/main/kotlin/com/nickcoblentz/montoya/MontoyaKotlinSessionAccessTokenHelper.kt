package com.nickcoblentz.montoya
import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.handler.*
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.sessions.ActionResult
import burp.api.montoya.http.sessions.SessionHandlingAction
import burp.api.montoya.http.sessions.SessionHandlingActionData
import com.nickcoblentz.montoya.settings.*
import de.milchreis.uibooster.model.Form
import de.milchreis.uibooster.model.FormBuilder
import java.util.regex.Pattern

//import kotlinx.serialization.Serializable;

class MontoyaKotlinSessionAccessTokenHelper : BurpExtension, SessionHandlingAction, /*ProxyResponseHandler,*/ HttpHandler {
//https://danaepp.com/writing-burp-extensions-in-kotlin

    private lateinit var HeaderValueSuffixSetting1: StringExtensionSetting
    private lateinit var HeaderValuePrefixSetting1: StringExtensionSetting
    private lateinit var HeaderNameSetting1: StringExtensionSetting
    private lateinit var HeaderValueSuffixSetting2: StringExtensionSetting
    private lateinit var HeaderValuePrefixSetting2: StringExtensionSetting
    private lateinit var HeaderNameSetting2: StringExtensionSetting
    private lateinit var PassiveNameSetting: BooleanExtensionSetting
    private lateinit var IgnoreEndpointsSetting: ListStringExtensionSetting
    private lateinit var ShouldIgnoreEndpointsSetting: BooleanExtensionSetting
    private lateinit var Api: MontoyaApi
    private var AccessToken = ""
    private lateinit var Logger: MontoyaLogger
    private val PluginName: String = "Session Handling: Access Token Helper"
    private lateinit var AccessTokenPatternSetting: StringExtensionSetting


    override fun initialize(api: MontoyaApi?) {
        if(api==null)
        {
            return
        }
        Api=api

        Logger = MontoyaLogger(api, LogLevel.DEBUG)
        Logger.debugLog( "Plugin Starting...")
        api.extension().setName(PluginName)
        api.http().registerSessionHandlingAction(this)

        AccessTokenPatternSetting = StringExtensionSetting(
            api,
            "Access Token RegEx Pattern",
            "BKSATH.pattern",
            "\"access_token\" *: *\"([^\"]+)\"",
            ExtensionSettingSaveLocation.PROJECT
        )
        HeaderNameSetting1 = StringExtensionSetting(
            api,
            "Name of First Header",
            "BKSATH.header",
            "Authorization",
            ExtensionSettingSaveLocation.PROJECT
        )
        HeaderValuePrefixSetting1 = StringExtensionSetting(
            api,
            "First Header Value Prefix (include your space)",
            "BKSATH.prefix",
            "Bearer ",
            ExtensionSettingSaveLocation.PROJECT
        )
        HeaderValueSuffixSetting1 = StringExtensionSetting(
            api,
            "First Header Value Suffix (include your space)",
            "BKSATH.suffix",
            "",
            ExtensionSettingSaveLocation.PROJECT
        )
        HeaderNameSetting2 = StringExtensionSetting(
            api,
            "Name of Second Header",
            "BKSATH.header2",
            "Authorization",
            ExtensionSettingSaveLocation.PROJECT
        )
        HeaderValuePrefixSetting2 = StringExtensionSetting(
            api,
            "Second Header Value Prefix (include your space)",
            "BKSATH.prefix2",
            "Bearer ",
            ExtensionSettingSaveLocation.PROJECT
        )
        HeaderValueSuffixSetting2 = StringExtensionSetting(
            api,
            "Second Header Value Suffix (include your space)",
            "BKSATH.suffix2",
            "",
            ExtensionSettingSaveLocation.PROJECT
        )
        PassiveNameSetting = BooleanExtensionSetting(
            api,
            "Use Passively For All Requests?",
            "BKSATH.passive",
            false,
            ExtensionSettingSaveLocation.PROJECT
        )
        IgnoreEndpointsSetting = ListStringExtensionSetting(
            api,
            "Ignore the following endpoints when applyting the token",
            "BKSATH.ignoreendpoints",
            mutableListOf<String>(),
            ExtensionSettingSaveLocation.PROJECT
        )
        ShouldIgnoreEndpointsSetting = BooleanExtensionSetting(
            api,
            "Ignore those endpoints?",
            "BKSATH.shouldignore",
            false,
            ExtensionSettingSaveLocation.PROJECT
        )
        val extensionSetting = listOf(HeaderNameSetting1,HeaderValuePrefixSetting1,HeaderValueSuffixSetting1,HeaderNameSetting2,HeaderValuePrefixSetting2,HeaderValueSuffixSetting2,AccessTokenPatternSetting,PassiveNameSetting,IgnoreEndpointsSetting,ShouldIgnoreEndpointsSetting)
        val gen = GenericExtensionSettingsFormGenerator(extensionSetting, PluginName)
        val settingsFormBuilder: FormBuilder = gen.getSettingsFormBuilder()
        settingsFormBuilder.startRow().addTextArea("Preview",previewFullHeader()).setID("_calculate").setDisabled().endRow()
        gen.addSaveCallback { formElement, form -> form.getById("_calculate").value = previewFullHeader() }
        val settingsForm: Form = settingsFormBuilder.run()

        api.userInterface().registerContextMenuItemsProvider(ExtensionSettingsContextMenuProvider(api, settingsForm))
        api.extension().registerUnloadingHandler(ExtensionSettingsUnloadHandler(settingsForm))
        //api.proxy().registerResponseHandler(this);
        api.http().registerHttpHandler(this)
        Logger.debugLog( "Finished")


    }

/*
    override fun handleResponseReceived(interceptedResponse: InterceptedResponse?): ProxyResponseReceivedAction {
        return ProxyResponseReceivedAction.continueWith(interceptedResponse)
    }

    override fun handleResponseToBeSent(interceptedResponse: InterceptedResponse): ProxyResponseToBeSentAction {
        if(interceptedResponse.request().isInScope) {
            if (interceptedResponse.bodyToString().contains("\"access_token\":\"")) {
                val bodyJson = JSONObject(interceptedResponse.bodyToString())
                _api?.logging()?.logToOutput(bodyJson.toString())
                _accessToken = bodyJson.getString("access_token")
                _api?.logging()?.logToOutput("Set new access token: $_accessToken")
            }
        }
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse)
    }
*/
    override fun name(): String {
        return PluginName
    }

    override fun performAction(actionData: SessionHandlingActionData): ActionResult {
        Logger.debugLog(this.javaClass.name, "=======================\nperformAction")
        var request = actionData.request()

        Logger.debugLog("---------------------------\nStage 1: Checking for Macros")
        if(actionData.macroRequestResponses().size>0) {
            Logger.debugLog("Found Macro Request/Response")
            for (httpReqRes in actionData.macroRequestResponses()) {
                if(httpReqRes.hasResponse())
                    updateAccessTokenIfFound(httpReqRes.response().toString());
            }
        }
        else
            Logger.debugLog("No macro found")

        Logger.debugLog("------------------------\nStage 2: Session Handling")
        if (AccessToken.isNotEmpty() && !urlShouldBeIgnored(request)) {
            Logger.debugLog("Access token non-empty: ${AccessToken}, valid URL (not ignore url): ${request.url()}")
            if(HeaderNameSetting1.currentValue.isNotBlank()) {
                Logger.debugLog("Access Token and Header1 Not Empty, adding header: ${HeaderNameSetting1.currentValue}: ${previewHeaderValue()}")
                if (request.hasHeader(HeaderNameSetting1.currentValue))
                    request =
                        request.withUpdatedHeader(HeaderNameSetting1.currentValue, previewHeaderValue())
                else
                    request =
                        request.withAddedHeader(HeaderNameSetting1.currentValue, previewHeaderValue())
            }
            else
                Logger.debugLog("Skipping ${HeaderNameSetting1.currentValue} header, empty")

            if(HeaderNameSetting2.currentValue.isNotBlank()) {
                Logger.debugLog("Access Token and Header2 Not Empty, adding header: ${HeaderNameSetting2.currentValue}: ${previewHeaderValue()}")
                if (request.hasHeader(HeaderNameSetting2.currentValue))
                    request =
                        request.withUpdatedHeader(HeaderNameSetting2.currentValue, previewHeaderValue(true))
                else
                    request =
                        request.withAddedHeader(HeaderNameSetting2.currentValue, previewHeaderValue(true))
            }
            else
                Logger.debugLog("Skipping ${HeaderNameSetting2.currentValue} header, empty")
        }

        Logger.debugLog("Done, returning")
        return ActionResult.actionResult(request, actionData.annotations())
    }

    fun urlShouldBeIgnored(request: HttpRequest) : Boolean {
        return ShouldIgnoreEndpointsSetting.currentValue && IgnoreEndpointsSetting.currentValue.isNotEmpty() && IgnoreEndpointsSetting.currentValue.contains(request.url())
    }

    fun updateAccessTokenIfFound(responseString: String)
    {
        //Logger.debugLog("response string:\n$responseString")
        val pattern = Pattern.compile(AccessTokenPatternSetting.currentValue, Pattern.CASE_INSENSITIVE)
        val matcher = pattern.matcher(responseString)
        while (matcher.find() && matcher.groupCount() > 0) {
            AccessToken = matcher.group(1)
            Logger.debugLog("Found Access Token: $AccessToken")
        }
    }

    private fun previewFullHeader() : String {
        return "${HeaderNameSetting2.currentValue}: ${previewHeaderValue()}\r\n${HeaderNameSetting1.currentValue}: ${previewHeaderValue()}"
    }

    private fun previewHeaderValue(secondHeader : Boolean = false) : String {
        val headerBuilder = StringBuilder()
        if(secondHeader) {
            headerBuilder.append(HeaderValuePrefixSetting2.currentValue)
            if(AccessToken.isEmpty())
                headerBuilder.append("ACCESS TOKEN HERE")
            else
                headerBuilder.append(AccessToken)
            headerBuilder.append(HeaderValueSuffixSetting2.currentValue)
        }
        else {
            headerBuilder.append(HeaderValuePrefixSetting1.currentValue)
            if(AccessToken.isEmpty())
                headerBuilder.append("ACCESS TOKEN HERE")
            else
                headerBuilder.append(AccessToken)
            headerBuilder.append(HeaderValueSuffixSetting1.currentValue)
        }

        return headerBuilder.toString()
    }
/*
    override fun handleResponseReceived(interceptedResponse: InterceptedResponse?): ProxyResponseReceivedAction {
        interceptedResponse?.let {
            updateAccessTokenIfFound(it.toString());
        }
        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    override fun handleResponseToBeSent(interceptedResponse: InterceptedResponse?): ProxyResponseToBeSentAction {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }
*/
    override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent?): RequestToBeSentAction {
        return RequestToBeSentAction.continueWith(requestToBeSent)
    }

    override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived?): ResponseReceivedAction {
        if(PassiveNameSetting.currentValue)
            responseReceived?.let {
                updateAccessTokenIfFound(it.toString());
            }
        return ResponseReceivedAction.continueWith(responseReceived)
    }
}