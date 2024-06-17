# MontoyaKotlinSessionAccessTokenHelper

- Record a macro that logs into an oauth provider
- Verify the json returning has `"access_token":"valuehere"` in the response
- Verify your endpoints are all added to the scope
- Create a session handling rule
  - add a rule that applies the extension to all requests
  - add a second rule that:
    - checks for the request to be in session
    - issues the current request
    - has a signature for detecting being out of session
    - if out of session, runs the login macro above
      - processes the output of the login macro using the extension
    - applies the extension to the current request
- Set your scope/tools