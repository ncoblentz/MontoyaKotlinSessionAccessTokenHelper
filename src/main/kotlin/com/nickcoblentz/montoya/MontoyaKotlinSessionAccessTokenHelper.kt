package com.nickcoblentz.montoya
import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.sessions.ActionResult
import burp.api.montoya.http.sessions.SessionHandlingAction
import burp.api.montoya.http.sessions.SessionHandlingActionData
import org.json.JSONObject

//import kotlinx.serialization.Serializable;

class MontoyaKotlinSessionAccessTokenHelper : BurpExtension, SessionHandlingAction {
//https://danaepp.com/writing-burp-extensions-in-kotlin

    private val _api: MontoyaApi? = null
    private var _accessToken = ""

    override fun initialize(_api: MontoyaApi?) {
        if(_api==null)
        {
            return
        }

        _api.extension().setName("Session Handling: Access Token Helper")
        _api.http().registerSessionHandlingAction(this)
        _api.logging().logToOutput("Loaded Successfully!")
        //val test: Serializable?;

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
        _api?.logging()?.logToOutput("performAction")
        var request = actionData.request()

        if(request.isInScope) {
            _api?.logging()?.logToOutput("is in scope")
            if(actionData.macroRequestResponses().size==1) {
                _api?.logging()?.logToOutput("Found Macro Request/Response of size 1")
                val response = actionData.macroRequestResponses()[0].response()
                if (response.bodyToString().contains("\"access_token\":\"")) {
                    val bodyJson = JSONObject(response.bodyToString())
                    _api?.logging()?.logToOutput(bodyJson.toString())
                    _accessToken = bodyJson.getString("access_token")
                    _api?.logging()?.logToOutput("Set new access token: $_accessToken")
                }
            }

            _api?.logging()?.logToOutput("Session Handling")
            if (_accessToken.isNotEmpty()) {
                _api?.logging()?.logToOutput("Not Empty, adding header")
                request = actionData.request().withUpdatedHeader("Authorization", "Bearer $_accessToken")
            }
        }
        return ActionResult.actionResult(request, actionData.annotations())
    }
}