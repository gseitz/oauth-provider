{-# LANGUAGE OverloadedStrings #-}

module Example where

import           Control.Arrow            (second)
import           Control.Concurrent       (forkIO)
import           Control.Concurrent.Chan
import           Control.Monad            (join)
import           Data.Functor             ((<$>))
import           Data.List                (intercalate)
import           Data.Maybe               (fromMaybe, isJust)
import           Data.Monoid              ((<>))
import Network
import           Network.HTTP.Types       (ok200, parseQueryText)
import           Network.Wai.Handler.Warp (run)

import           Network.Wai.OAuth
import           Network.Wai.OAuth.Types

import qualified Data.ByteString          as B
import qualified Data.ByteString.Lazy     as BL
import qualified Data.Text                as T
import qualified Data.Text.Encoding       as E
import qualified Data.Vault.Lazy          as V
import qualified Network.HTTP.Conduit     as HC
import qualified Network.Wai              as W

main :: IO ()
main = do
    server <- forkIO warpApp
    client <- forkIO clientApp
    _ <- readLn :: IO Int
    return ()

warpApp :: IO ()
warpApp = do
    chan <- newChan
    paramsKey <- V.newKey
--     let config = threeLeggedConfig consumerLookup accessLookup emptyTokenLookup tokenGenerator timestampCheck [HMAC_SHA1] noopCallbackStore verifierLookup
    let config = twoLeggedConfig consumerLookup accessLookup requestLookup tokenGenerator timestampCheck [Plaintext]
    run 3000 $ withOAuth paramsKey config [["protected"], ["users", "VIP"]] $ warpy paramsKey config chan

warpy :: V.Key OAuthParams -> OAuthConfig IO -> Chan () -> W.Application
warpy key config chan req = do
    (eith, _) <- case W.pathInfo req of
        ["request"] -> runOAuth config req twoLeggedRequestTokenRequest
        ["access"] -> runOAuth config req twoLeggedAccessTokenRequest
        _ -> return (Right . mkResponse $ isProtected <> " : " <> fromMaybe "successful request" echo, req)
    return $ either errorAsResponse id eith
  where
    isProtected = maybe "unprotected" (const "protected") $ V.lookup key (W.vault req)
    echo = join $ lookup "echo" $ W.queryString req
        --config = oneLeggedConfig consumerLookup timestampCheck [HMAC_SHA1]
--     errorResponse <- liftIO $ runOAuthM config req $ threeLeggedAccessTokenRequest
--     return $ either (errorAsResponse) (id) errorResponse

tokenGenerator :: Monad m => TokenGenerator m
tokenGenerator RequestToken _ = return ("request_key", "request_secret")
tokenGenerator AccessToken _ = return ("access_key", "access_secret")

verifierLookup :: Monad m => VerifierLookup m
verifierLookup _ = return "foobar"

mkResponse :: B.ByteString -> W.Response
mkResponse = W.responseLBS ok200 [] . BL.fromStrict

consumerLookup :: Monad m => SecretLookup ConsumerKey m
consumerLookup (ConsumerKey key) = return $ case key of
    "consumer_key" -> Right "consumer_secret"
    key -> Left $ InvalidConsumerKey key

accessLookup :: Monad m => SecretLookup AccessTokenKey m
accessLookup (AccessTokenKey key) = return $ case key of
    "access_key" -> Right "access_secret"
    key -> Left $ InvalidToken key

requestLookup :: Monad m => SecretLookup RequestTokenKey m
requestLookup (RequestTokenKey key) = return $ case key of
    "request_key" -> Right "request_secret"
    key -> Left $ InvalidToken key

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
    let url = buildURL path $ [
            ("oauth_consumer_key", "consumer_key"),
            ("oauth_token", T.unpack token),
            ("oauth_signature_method", "PLAINTEXT"),
            ("oauth_signature", "consumer_secret%26" ++ T.unpack secret)
            ]
    request' <- HC.parseUrl $ url
    let request = request' { HC.checkStatus = \_ _ _ -> Nothing }
    resp <- HC.withManager $ HC.httpLbs request
    return $ HC.responseBody resp

buildURL :: String -> [(String, String)] -> String
buildURL path params = "http://localhost:3000" ++ path ++ "?" ++ (intercalate "&" $ map (\(k,v) -> k ++ "=" ++ v) params)


query :: B.ByteString -> [(T.Text, T.Text)]
query = fmap (second (fromMaybe "")) . parseQueryText
