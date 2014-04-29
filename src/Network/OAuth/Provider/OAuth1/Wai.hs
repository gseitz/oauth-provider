{-# LANGUAGE OverloadedStrings #-}
module Network.OAuth.Provider.OAuth1.Wai
    (
      withOAuth
    , convertAndExecute
    , toWaiResponse
    ) where

import           Control.Arrow              (second)
import           Control.Error.Util         (hush)
import           Control.Monad.IO.Class     (MonadIO, liftIO)
import           Data.Attoparsec.Char8      (Parser)
import           Data.Functor               ((<$>))
import           Data.IORef.Lifted          (newIORef, readIORef, writeIORef)
import           Data.List                  (isPrefixOf)
import           Data.Maybe                 (fromMaybe)
import           Data.Monoid                (mconcat)
import           Data.Text                  (Text)
import           Network.HTTP.Types         (parseSimpleQuery, queryToQueryText)
import           Network.Wai                (Middleware, Request, Response,
                                             isSecure, pathInfo, queryString,
                                             requestBody, requestHeaderHost,
                                             requestHeaders, requestMethod,
                                             responseLBS, vault)
import           Network.Wai.Parse          (RequestBodyType (..),
                                             getRequestBodyType)

import qualified Data.Attoparsec.Char8      as A
import qualified Data.ByteString.Lazy       as BL
import qualified Data.Conduit               as C
import qualified Data.Conduit.List          as CL
import qualified Data.Text.Encoding         as E
import qualified Data.Vault.Lazy            as V


import           Network.OAuth.Provider.OAuth1
import           Network.OAuth.Provider.OAuth1.Internal
import           Network.OAuth.Provider.OAuth1.Types


-- | 'withOAuth' acts as a 'Middleware' and intercepts requests to check for
-- the validity of the provided OAuth parameters. The given 'PathParts' are
-- used as prefixes for paths that are only accessible with a valid OAuth request.
--
-- Notice that this just triggers "oauth-provider" to check whether the request
-- itself is a syntactically valid OAuth request with valid and authenticated tokens.
-- The actual authorization needs to be done by the application itself.
-- For this purpose, the extracted 'OAuthParams' can be accessed with the given
-- 'V.Key' 'OAuthParams' from the 'Request''s 'V.Vault' further down the line.
withOAuth ::
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
        then convertAndExecute req executeOAuthRequest
        else app req
  where
    -- check if any of the supplied paths is a prefix of the current request path
    needsProtection = any (`isPrefixOf` pathInfo req) prefixes
    setParams r p = r { vault = V.insert paramsKey p (vault r) }
    executeOAuthRequest req' oauthReq = do
        errorOrParams <- runOAuth (cfg, oauthReq) authenticated
        either errorAsWaiResponse (app . setParams req') errorOrParams

-- | Converts the given 'Request' and executes the action function.
convertAndExecute :: Request -- ^ The original Wai 'Request'.
    -> (Request -> OAuthRequest -> IO Response)
    -- ^ The action function. Since converting a 'Request' to an 'OAuthRequest'
    -- potentially reads the request body, a copy of the original 'Request'
    -- with the body restored (the content is replayed) for further usage
    -- is passed to this action function as well.
    -> IO Response
convertAndExecute req action = do
    (req', errorOrOAuthReq) <- toOAuthRequest req
    either errorAsWaiResponse (action req') errorOrOAuthReq

errorAsWaiResponse :: OAuthError -> IO Response
errorAsWaiResponse = return . toWaiResponse . errorAsResponse

extractFormBodyParameters :: Request -> IO (Request, SimpleQueryText)
extractFormBodyParameters req =
    case getRequestBodyType req of
        Just UrlEncoded -> do
            (body, replayedBody) <- liftIO $ replay req
            let req' = req { requestBody = replayedBody }
                params = parseSimpleQuery $ mconcat body
                result = [(E.decodeUtf8 k, E.decodeUtf8 v) | (k, v) <- params]
            return (req', result)
        _               -> return (req, [])
  where
    replay req' = do
        body <- requestBody req' C.$$ CL.consume
        ichunks <- newIORef body
        let rbody = do
                chunks <- readIORef ichunks
                case chunks of
                    [] -> return ()
                    x:xs -> do
                        writeIORef ichunks xs
                        C.yield x
                        rbody
        return (body, rbody)

toOAuthRequest :: Request -> IO (Request, Either OAuthError OAuthRequest)
toOAuthRequest req = do
    (req', bodyParams) <- extractFormBodyParameters req
    let authHeaderParams = fromMaybe [] $ parseAuthentication <$> lookup "Authentication" (requestHeaders req)
        hostPort = (hush . A.parseOnly hostPortParser) =<< requestHeaderHost req
        mkRequest (host, port) = OAuthRequest (isSecure req) (pathInfo req) (query req) bodyParams authHeaderParams host port (requestMethod req)
    return (req', maybe (Left MissingHostHeader) (Right . mkRequest) hostPort)

-- | Creates a 'Response' out of an 'OAuthResponse'.
toWaiResponse :: OAuthResponse -> Response
toWaiResponse (OAuthResponse status headers content) = responseLBS status headers (BL.fromStrict content)

hostPortParser :: Parser (Text, Int)
hostPortParser = do
    host <- A.takeWhile (':' /=)
    _ <- A.char ':'
    port <- A.decimal
    return (E.decodeUtf8 host, port)

query :: Request -> SimpleQueryText
query = fmap (second (fromMaybe "")) . queryToQueryText . queryString
