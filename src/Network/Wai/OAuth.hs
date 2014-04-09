{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE TupleSections         #-}
{-# LANGUAGE ViewPatterns          #-}

-- | This module provides the basic building blocks to build WAI applications with OAuth 1.0a cababilities.
--
-- "wai-oauth" implements the /One Legged/, /Two Legged/, and /Three Legged/ flows described
-- in <https://github.com/Mashape/mashape-oauth/blob/master/FLOWS.md>.
module Network.Wai.OAuth
    (
      withOAuth
    , oneLegged
    , twoLeggedAccessTokenRequest
    , twoLeggedRequestTokenRequest
    , threeLeggedAccessTokenRequest
    , threeLeggedRequestTokenRequest
    , authenticated
    ) where

import           Control.Error.Util         (note)
import           Control.Monad              (mfilter, unless)
import           Control.Monad.IO.Class     (MonadIO)
import           Control.Monad.Reader       (ask)
import           Control.Monad.State        (get)
import           Control.Monad.Trans.Class  (lift)
import           Control.Monad.Trans.Either (EitherT (..))
import           Data.Attoparsec.Char8      (decimal, parseOnly)
import           Data.ByteString            (ByteString)
import           Data.Either.Combinators    (mapLeft)
import           Data.Functor               ((<$>))
import           Data.List                  (isPrefixOf)
import           Data.Maybe                 (fromMaybe)
import           Data.Monoid                ((<>))
import           Network.HTTP.Types         (badRequest400, hContentType, ok200,
                                             unauthorized401)
import           Network.Wai                (Middleware, Request, Response,
                                             pathInfo, requestMethod,
                                             responseLBS, vault)

import qualified Data.ByteString            as B
import qualified Data.ByteString.Lazy       as BL
import qualified Data.Text                  as T
import qualified Data.Text.Encoding         as E
import qualified Data.Vault.Lazy            as V

import           Network.Wai.OAuth.Internal
import           Network.Wai.OAuth.Types

-- | 'withOAuth' acts as a 'Middleware' and intercepts requests to check for
-- the validity of the provided OAuth parameters. The given 'PathParts' are
-- used as prefixes for paths that are only accessible with a valid OAuth request.
--
-- Notice that this just triggers "wai-oauth" to check whether the request
-- itself is a syntactically valid OAuth request with valid and authenticated tokens.
-- The actual authorization needs to be done by the application itself.
-- For this purpose, the extracted 'OAuthParams' can be accessed with the given
-- 'V.Key' 'OAuthParams' from the 'Request''s 'V.Vault'.
withOAuth :: MonadIO m =>
    V.Key OAuthParams -- ^ The 'V.Key' with which the 'OAuthParams' can be
                      -- looked up in the request handling of an
                      -- 'Application' further down the line.
    -> OAuthConfig IO -- ^ An 'OAuthConfig' is best created with one of the
                      -- provided functions 'oneLeggedConfig',
                      -- 'twoLeggedConfig', 'threeLeggedConfig'.
    -> [PathParts]    -- ^ These are the prefixes for request paths that need to
                      -- be authenticated OAuth requests.
    -> Middleware
withOAuth paramsKey cfg prefixes app req =
    if needsProtection
        then do
                (errorOrParams, req') <- runOAuthM cfg req authenticated
                either (return . errorAsResponse) (app . setParams req') errorOrParams
        else app req
  where
    -- check if any of the supplied paths is a prefix of the current request path
    needsProtection = any (`isPrefixOf` pathInfo req) prefixes
    setParams r p = r { vault = V.insert paramsKey p (vault r) }

parseRequest :: MonadIO m => OAuthM m OAuthState
parseRequest = do
    request <- get
    (oauths, rest) <- splitOAuthParams
    url <- oauthEither $ generateNormUrl request
    let getM name = mfilter ( /= "") $ E.encodeUtf8 <$> lookup name oauths
        getE name = note (MissingParameter name) $ getM name
        getOrEmpty name = fromMaybe "" $ getM name
    oauth  <- oauthEither $ do
        signMeth <- getE "oauth_signature_method" >>= extractSignatureMethod
        signature <- Signature <$> getE "oauth_signature"
        consKey <- ConsumerKey <$> getE "oauth_consumer_key"
        timestamp <- maybe (Right Nothing) (fmap Just) (parseTS <$> getM "oauth_timestamp")
        return $ OAuthParams consKey (getOrEmpty "oauth_token") signMeth
            (Callback <$> getM "oauth_callback") (Verifier <$> getM "oauth_verifier")
            signature (Nonce <$> getM "oauth_nonce") timestamp
    return OAuthState { oauthRawParams = oauths, reqParams = rest, reqUrl = url
                      , reqMethod = requestMethod request, oauthParams = oauth }
  where
    parseTS = mapLeft (const InvalidTimestamp) . parseOnly decimal

-- | Checks that the request is signed by the final consumer-accesstoken secrets.
authenticated :: MonadIO m => OAuthM m OAuthParams
authenticated = do
    OAuthConfig {..} <- ask
    processOAuthRequest (bsSecretLookup AccessTokenKey cfgAccessTokenSecretLookup)

noProcessing :: Monad m => OAuthParams -> OAuthM m ()
noProcessing = const (return ())

processOAuthRequest :: MonadIO m => SecretLookup ByteString m -> OAuthM m OAuthParams
processOAuthRequest tokenLookup = do
    oauth <- parseRequest
    OAuthConfig {..} <- ask
    _ <- verifyOAuthSignature cfgConsumerSecretLookup tokenLookup oauth
    _ <- OAuthT . EitherT . lift . lift $ do
        maybeError <- cfgNonceTimestampCheck $ oauthParams oauth
        return $ maybe (Right ()) Left  maybeError
    return $ oauthParams oauth

processTokenCreationRequest :: MonadIO m =>
    SecretLookup ByteString m
    -> (ConsumerKey -> m (Token, Secret)) -> (OAuthParams -> OAuthM m ())
    -> OAuthM m [(ByteString, ByteString)]
processTokenCreationRequest tokenLookup secretCreation customProcessing = do
    params <- processOAuthRequest tokenLookup
    _      <- customProcessing params
    (Token token, Secret secret) <- liftOAuthT $ secretCreation $ opConsumerKey params
    return [("oauth_token", token), ("oauth_token_secret", secret)]


-- | The one legged flow requires an empty /oauth_token/ parameter.
oneLegged :: MonadIO m => OAuthM m OAuthParams
oneLegged = authenticated

twoLeggedRequestTokenRequest :: MonadIO m => OAuthM m Response
twoLeggedRequestTokenRequest = do
    OAuthConfig {..} <- ask
    twoLegged emptyTokenLookup (cfgTokenGenerator RequestToken)

twoLeggedAccessTokenRequest :: MonadIO m => OAuthM m Response
twoLeggedAccessTokenRequest = do
    OAuthConfig {..} <- ask
    twoLegged (bsSecretLookup RequestTokenKey cfgRequestTokenSecretLookup)
              (cfgTokenGenerator AccessToken)

twoLegged :: MonadIO m => SecretLookup ByteString m -> (ConsumerKey -> m (Token, Secret)) -> OAuthM m Response
twoLegged tokenLookup secretCreation = do
    responseString <- processTokenCreationRequest tokenLookup secretCreation noProcessing
    return $ mkResponse200 responseString

threeLeggedRequestTokenRequest :: MonadIO m => OAuthM m Response
threeLeggedRequestTokenRequest = do
    OAuthConfig {..} <- ask
    responseParams <- processTokenCreationRequest emptyTokenLookup (cfgTokenGenerator RequestToken) noProcessing
    return $ mkResponse200 $ ("oauth_callback_confirmed", "true") : responseParams

threeLeggedAccessTokenRequest :: MonadIO m => OAuthM m Response
threeLeggedAccessTokenRequest = do
    OAuthConfig {..} <- ask
    let verifierCheck params = do
            storedVerifier <- lift $ cfgVerifierLookup (opConsumerKey params, opToken params)
            case opVerifier params of
                Just ((==) storedVerifier -> True) -> oauthEither $ Right ()
                Just wrongVerifier               -> oauthEither $ Left (InvalidVerifier wrongVerifier)
                Nothing                          -> oauthEither $ Left (MissingParameter "oauth_verifier")
    responseParams <- processTokenCreationRequest
        (bsSecretLookup RequestTokenKey cfgRequestTokenSecretLookup)
        (cfgTokenGenerator AccessToken) verifierCheck
    return $ mkResponse200 responseParams


mkResponse200 :: [(ByteString, ByteString)] -> Response
mkResponse200 params = responseLBS ok200 [(hContentType, "application/x-www-form-urlencoded")] (BL.fromStrict body)
  where
    body = B.intercalate "&" $ fmap paramString params
    paramString (a,b) = B.concat [a, "=", b]


verifyOAuthSignature :: MonadIO m =>
    SecretLookup ConsumerKey m
    -> SecretLookup ByteString m
    -> OAuthState
    -> OAuthM m ()
verifyOAuthSignature consumerLookup tokenLookup  (OAuthState oauthRaw rest url method oauth) = do
    cons <- wrapped consumerLookup $ opConsumerKey oauth
    token <- wrapped tokenLookup $ opToken oauth
    let secrets = (cons, token)
        cleanOAuths = filter ((/=) "oauth_signature" . fst) oauthRaw
    let serverSignature = genOAuthSignature oauth secrets method url (cleanOAuths <> rest)
        clientSignature = opSignature oauth
    unless (clientSignature == serverSignature) $
        oauthEither $ Left $ InvalidSignature clientSignature
  where
    wrapped f = OAuthT . EitherT . lift . lift . f


errorAsResponse :: OAuthError -> Response
errorAsResponse err = case err of
    -- 400 - Bad Request
    UnsupportedParameter _ -> r400
    UnsupportedSignatureMethod _ -> r400
    MissingParameter _ -> r400
    MissingHostHeader -> r400
    DuplicateParameter _ -> r400
    MultipleOAuthParamLocations -> r400
    InvalidTimestamp -> r400
    -- 401 - Unauthorized
    InvalidToken _ -> r401
    UsedNonce -> r401
    InvalidConsumerKey _ -> r401
    InvalidSignature _ -> r401
    InvalidVerifier _ -> r401
    ExpiredRequest -> r401
    ExpiredToken _ -> r401
  where
    r400 = resp badRequest400
    r401 = resp unauthorized401
    resp status = responseLBS status [] $ BL.fromStrict $ E.encodeUtf8 $ T.pack $ show err


