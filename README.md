# Session Access Token Helper Burp Extension

_By [Nick Coblentz](https://www.linkedin.com/in/ncoblentz/)_

__The Session Access Token Helper Burp Extension is made possible by [Virtue Security](https://www.virtuesecurity.com), the Application Penetration Testing consulting company I work for.__

## About

The __Session Access Token Helper Burp Extension__:
- Captures and remembers access tokens in HTTP responses based on a regex you define (and is saved persistently with your project)
- Allows you to define a session macro that applies that access token as a header with a header name, prefix and suffix you define (also saved with your project)

## How to Use It

- Build it with `gradlew shadowJar`
- Add the extension in burp from the `build/libs/MontoyaKotlinAccessTokenHelper-x.y-all.jar` folder where `x.y` represents the build version
- Configure your settings by right-clicking on any HTTP request and going to Extensions &gt; Session Handling: Access Token Helper &gt; Settings 

### Using the plugin as a Session Handling Action

This mode of operation will watch for access tokens and apply them to any request covered by your session handling rule as described below

- In the session handling rules within Burp Suite's settings, Add a new rule, and add the action: "Invoke a Burp Extension". Choose "Access Token Helper"
- In the Session Access Token Helper's settings, check mark "Use Passively For All Requests?"`
- Configure your scope and tools you want it to apply to

### Using the plugin with a Login Macro

This mode of operation tries to apply the access token to all new requests and if the request fails you "check session is valid" rule, it uses a login macro you define, obtains the access token from that macro, and applies it the request and re-issues it.

- Record a macro that logs into an application (this is a core feature of burp suite and is beyond the scope of this document)
- Verify the json returning has `"access_token":"access token here"` in the response (or a custom pattern you change in this plugin's settings)
- In the session handling rules within Burp Suite's settings, Add a new rule, and add the action: "Invoke a Burp Extension". Choose "Access Token Helper"
- Configure your scope and tools you want it to apply to
- Create second session rule using the "check session is valid" rule
  - Select "Issue Current Request"
  - Configure the "inspect response to determine session validity" to identify responses indicating you are no longer logged into the application
  - Select "if session is invalid, perform the action below", "Run a macro", Choose the login macro you created above
  - Select "After running the macro, invoke a burp extension handler", and select "Access Token Helper" 




