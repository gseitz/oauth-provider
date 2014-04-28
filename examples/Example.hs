{-# LANGUAGE OverloadedStrings #-}

module Example where

import           Control.Arrow            (second)
import           Control.Concurrent       (forkIO)
import           Control.Monad            (join)
import           Data.List                (intercalate)
import           Data.Maybe               (fromMaybe)
import           Data.Monoid              ((<>))
import           Network.HTTP.Types       (ok200, parseQueryText)
import           Network.Wai.Handler.Warp (run)

import           Network.Wai.OAuth
import           Network.Wai.OAuth.Types
import Network.Wai.OAuth.Wai

import qualified Data.ByteString          as B
import qualified Data.ByteString.Lazy     as BL
import qualified Data.Text                as T
import qualified Data.Vault.Lazy          as V
import qualified Network.HTTP.Conduit     as HC
import qualified Network.Wai              as W

main :: IO ()
main = do
    _  <- forkIO warpApp2Legged
    _ <- forkIO clientApp
    _ <- readLn :: IO Int
    return ()

warpApp2Legged :: IO ()
warpApp2Legged = do
    paramsKey <- V.newKey
    -- Setting up the 'OAuthConfig'. We only use 'Plaintext' as supported 'SignatureMethod',
    -- as it makes putting the requests together a lot easier.
    let config = twoLeggedConfig consumerLookup accessLookup requestLookup tokenGenerator timestampCheck [Plaintext]
    run 3000 $ withOAuth paramsKey config [["protected"], ["users", "VIP"]] $ warpy paramsKey config

warpy :: V.Key OAuthParams -> OAuthConfig IO -> W.Application
warpy key config waiRequest =
    convertAndExecute waiRequest $ \ waiRequest' oauthRequest -> do
        eith <- case W.pathInfo waiRequest' of
            ["request"] -> runOAuth (config, oauthRequest) twoLeggedRequestTokenRequest
            ["access"] -> runOAuth (config, oauthRequest) twoLeggedAccessTokenRequest
            _ -> return $ Right . mkResponse $ isProtected <> " : " <> fromMaybe "successful request" echo
        return . toWaiResponse $ either errorAsResponse id eith
  where
    isProtected = maybe "unprotected" (const "protected") $ V.lookup key (W.vault waiRequest)
    echo = join $ lookup "echo" $ W.queryString waiRequest

tokenGenerator :: Monad m => TokenGenerator m
tokenGenerator RequestToken _ = return ("request_key", "request_secret")
tokenGenerator AccessToken _ = return ("access_key", "access_secret")

verifierLookup :: Monad m => VerifierLookup m
verifierLookup _ = return "foobar"

mkResponse :: B.ByteString -> OAuthResponse
mkResponse = OAuthResponse ok200 []

-- | Action to lookup the consumer secret. In an application, this probably
-- will be a database lookup.
consumerLookup :: Monad m => SecretLookup ConsumerKey m
consumerLookup (ConsumerKey key) = return $ case key of
    "consumer_key" -> Right "consumer_secret"
    k -> Left $ InvalidConsumerKey k

-- | Action to lookup the access token secret. In an application, this probably
-- will be a database lookup.
accessLookup :: Monad m => SecretLookup AccessTokenKey m
accessLookup (AccessTokenKey key) = return $ case key of
    "access_key" -> Right "access_secret"
    k -> Left $ InvalidToken k

-- | Action to lookup the request token secret. In an application, this probably
-- will be a database lookup.
requestLookup :: Monad m => SecretLookup RequestTokenKey m
requestLookup (RequestTokenKey key) = return $ case key of
    "request_key" -> Right "request_secret"
    k -> Left $ InvalidToken k

-- | This action should check in a request log whether the given consumer,
-- token, nonce, and timestamp haven never been used before.
timestampCheck :: Monad m => NonceTimestampCheck m
timestampCheck _ = return Nothing

clientApp :: IO ()
clientApp = do
    putStrLn "-- Accessing unprotected resource"
    print =<< executeRequest "/unprotected" "I made this up" "very secret. wow."
    putStrLn "-- Trying to access protected resource with made up tokens"
    print =<< executeRequest "/protected" "I made this" "up"
    (reqTok, reqSec) <- acquireRequestToken
    (accTok, accSec) <- acquireAccessToken reqTok reqSec
    putStrLn "-- Accessing protected resource with acquired AccessToken after 2-legged flow"
    print =<< executeRequest "/protected" accTok accSec
    return ()

acquireRequestToken :: IO (T.Text, T.Text)
acquireRequestToken = acquireCredentials "/request" "" ""

acquireAccessToken :: T.Text -> T.Text -> IO (T.Text, T.Text)
acquireAccessToken = acquireCredentials "/access"

acquireCredentials :: String -> T.Text -> T.Text -> IO (T.Text, T.Text)
acquireCredentials path tok sec = do
    resp <- executeRequest path tok sec
    let params = query $ BL.toStrict resp
        tok' = fromMaybe (error "no token") $ lookup "oauth_token" params
        sec' = fromMaybe (error "no secret") $ lookup "oauth_token_secret" params
    return (tok', sec')

executeRequest:: String -> T.Text -> T.Text -> IO BL.ByteString
executeRequest path token secret = do
    let url = buildURL path [
            ("oauth_consumer_key", "consumer_key"),
            ("oauth_token", T.unpack token),
            ("oauth_signature_method", "PLAINTEXT"),
            ("oauth_signature", "consumer_secret%26" ++ T.unpack secret)
            ]
    request' <- HC.parseUrl url
    let request = request' { HC.checkStatus = \_ _ _ -> Nothing }
    resp <- HC.withManager $ HC.httpLbs request
    return $ HC.responseBody resp

buildURL :: String -> [(String, String)] -> String
buildURL path params = "http://localhost:3000" ++ path ++ "?" ++ intercalate "&" (map (\(k,v) -> k ++ "=" ++ v) params)


query :: B.ByteString -> [(T.Text, T.Text)]
query = fmap (second (fromMaybe "")) . parseQueryText
