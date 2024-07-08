package com.nickcoblentz.montoya
import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.sessions.ActionResult
import burp.api.montoya.http.sessions.SessionHandlingAction
import burp.api.montoya.http.sessions.SessionHandlingActionData
import com.nickcoblentz.montoya.settings.*
import de.milchreis.uibooster.model.Form
import de.milchreis.uibooster.model.FormBuilder
import de.milchreis.uibooster.model.FormElement
import java.util.function.BiConsumer
import java.util.regex.Pattern

//import kotlinx.serialization.Serializable;

class MontoyaKotlinSessionAccessTokenHelper : BurpExtension, SessionHandlingAction {
//https://danaepp.com/writing-burp-extensions-in-kotlin

    private lateinit var HeaderValueSuffixSetting: StringExtensionSetting
    private lateinit var HeaderValuePrefixSetting: StringExtensionSetting
    private lateinit var HeaderNameSetting: StringExtensionSetting
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

        Logger = MontoyaLogger(api, MontoyaLogger.DebugLogLevel)
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
        HeaderNameSetting = StringExtensionSetting(
            api,
            "Name of Header",
            "BKSATH.header",
            "Authorization",
            ExtensionSettingSaveLocation.PROJECT
        )
        HeaderValuePrefixSetting = StringExtensionSetting(
            api,
            "Header Value Prefix (include your space)",
            "BKSATH.prefix",
            "Bearer ",
            ExtensionSettingSaveLocation.PROJECT
        )
        HeaderValueSuffixSetting = StringExtensionSetting(
            api,
            "Header Value Suffix (include your space)",
            "BKSATH.suffix",
            "",
            ExtensionSettingSaveLocation.PROJECT
        )
        val extensionSetting = listOf(HeaderNameSetting,AccessTokenPatternSetting,HeaderValuePrefixSetting,HeaderValueSuffixSetting)
        val gen = GenericExtensionSettingsFormGenerator(extensionSetting, PluginName)
        val settingsFormBuilder: FormBuilder = gen.settingsFormBuilder
        settingsFormBuilder.startRow().addTextArea(previewFullHeader()).setID("_calculate").setDisabled().endRow()
        gen.addSaveCallback(BiConsumer { formElement, form ->  form.getById("_calculate").value = previewFullHeader() })
        val settingsForm: Form = settingsFormBuilder.run()

        api.userInterface().registerContextMenuItemsProvider(ExtensionSettingsContextMenuProvider(api, settingsForm))
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
        return "Access Token Helper"
    }

    override fun performAction(actionData: SessionHandlingActionData): ActionResult {
        Logger.debugLog(this.javaClass.name, "performAction")
        var request = actionData.request()

        if(request.isInScope) {
            Logger.debugLog("is in scope")
            if(actionData.macroRequestResponses().size>0) {
                Logger.debugLog("Found Macro Request/Response")
                for (httpReqRes in actionData.macroRequestResponses()) {
                    val response = httpReqRes.response()
                    val responseString = response.toString()
                    //Logger.debugLog("response string:\n$responseString")
                    val pattern = Pattern.compile(AccessTokenPatternSetting.currentValue, Pattern.CASE_INSENSITIVE)
                    val matcher = pattern.matcher(responseString)
                    while (matcher.find() && matcher.groupCount() > 0) {
                        AccessToken = matcher.group(1)
                        Logger.debugLog("Found Access Token: $AccessToken")
                    }
                    /*
                if (response.bodyToString().contains("\"access_token\":\"")) {
                    val bodyJson = JSONObject(response.bodyToString())
                    Logger?.debugLog( bodyJson.toString())
                    AccessToken = bodyJson.getString("access_token")
                    Logger?.debugLog( "Set new access token: $AccessToken")
                }*/
                }
            }

            Logger.debugLog( "Session Handling")
            if (AccessToken.isNotEmpty()) {
                Logger.debugLog( "Not Empty, adding header: ${HeaderNameSetting.currentValue}: ${previewHeaderValue()}")
                request = actionData.request().withUpdatedHeader(HeaderNameSetting.currentValue, previewHeaderValue())
            }
        }
        return ActionResult.actionResult(request, actionData.annotations())
    }

    private fun previewFullHeader() : String {
        return "${HeaderNameSetting.currentValue}: ${previewHeaderValue()}"
    }

    private fun previewHeaderValue() : String {
        val headerBuilder = StringBuilder()
        headerBuilder.append(HeaderValuePrefixSetting.currentValue)
        if(AccessToken.isEmpty())
            headerBuilder.append("ACCESS TOKEN HERE")
        else
            headerBuilder.append(AccessToken)
        headerBuilder.append(HeaderValueSuffixSetting.currentValue)
        return headerBuilder.toString()
    }
}