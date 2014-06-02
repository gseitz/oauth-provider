# oauth-provider [![Build Status](https://travis-ci.org/gseitz/oauth-provider.svg)](https://travis-ci.org/gseitz/oauth-provider)

## Introduction

*oauth-provider* is a web-framework agnostic library for building server
    applications with OAuth authentication. Only the [OAuth 1.0](http://tools.ietf.org/html/rfc5849)
    standard is currently supported.


## Usage

To use *oauth-provider*, pick an integration package from the list below depending
    on you web-framework of choice. Typical steps to do are:

 * Build up an `OAuthConfiguration` value for either 1-, 2-, or 3-legged authentication.
   * This entails building up various monadic actions for looking up the various token secrets, generating token/secret pairs, checking timestamp and nonce for uniqueness, etc...
 * Route requests to generate request tokens or access tokens to the provided functions.
   * The 1-legged flow only uses the consumer token, but neither request or access token.
   * `twoLeggedRequestTokenRequest`, `twoLeggedAccessTokenRequest` for 2-legged authentication
   * `threeLeggedRequestTokenRequest`, `threeLeggedAccessTokenRequest` for 3-legged authentication
 * Route all requests to "protected" resources via the `authenticated` function, which takes care of checking the request for valid authentication credentials.


## Examples

*oauth-provider* is not tied to any specifc web-framework. It rather aims to
    provide the building blocks for building web-framework specific integration
    packages.

There are integrations packages (including examples) for the following 2 web-frameworks:

  * Snap: [oauth-provider-snap](https://github.com/gseitz/oauth-provider-snap)
  * WAI (Yesod, Scotty): [oauth-provider-wai](https://github.com/gseitz/oauth-provider-wai)
