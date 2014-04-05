{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TupleSections     #-}
module Network.Wai.OAuth.Internal where

import           Control.Applicative        ((<|>))
import           Control.Arrow              (second)
import           Control.Error.Util         (note)
import           Control.Monad              (mfilter)
import           Control.Monad.State        (get, modify)
import           Control.Monad.Trans        (MonadIO, lift, liftIO)
import           Control.Monad.Trans.Either (hoistEither)
import           Data.Attoparsec.Char8      hiding (isDigit)
import           Data.ByteString            (ByteString)
import           Data.Char                  (isAlpha, isAscii, isDigit)
import           Data.Digest.Pure.SHA       (bytestringDigest, hmacSha1)
import           Data.IORef.Lifted          (newIORef, readIORef, writeIORef)
import           Data.List                  (find, group, partition, sort)
import           Data.Maybe                 (fromMaybe)
import           Data.Monoid                (mconcat)
import           Data.Text                  (Text)
import           Debug.Trace
import           Network.HTTP.Types         (parseSimpleQuery, queryToQueryText,
                                             urlDecode)
import           Network.Wai                (Request, isSecure, pathInfo,
                                             queryString, requestBody,
                                             requestHeaderHost, requestHeaders)
import           Network.Wai.Parse          (RequestBodyType (..),
                                             getRequestBodyType)

import qualified Data.ByteString            as B
import qualified Data.ByteString.Base16     as B16
import qualified Data.ByteString.Base64     as B64
import qualified Data.ByteString.Lazy       as BL
import qualified Data.Conduit               as C
import qualified Data.Conduit.List          as CL
import qualified Data.Text                  as T
import qualified Data.Text.Encoding         as E

import           Network.Wai.OAuth.Types

bsSecretLookup :: Monad m => (ByteString -> t) -> SecretLookup t m -> SecretLookup ByteString m
bsSecretLookup f l = l . f

data OAuthState = OAuthState
    { oauthRawParams :: SimpleQueryText
    , reqParams      :: SimpleQueryText
    , reqUrl         :: ByteString
    , reqMethod      :: ByteString
    , oauthParams    :: OAuthParams
    }

genOAuthSignature :: OAuthParams -> Secrets -> RequestMethod -> NormalizedURL -> SimpleQueryText -> Signature
genOAuthSignature OAuthParams {..} secrets method normUrl params = signature
  where
    signature = mkSignature opSignatureMethod secrets baseString
    baseString = genSignatureBase method normUrl paramString
    paramString = genParamString params

mkSignature :: SignatureMethod -> Secrets -> ByteString -> Signature
mkSignature signatureMethod (consSecret, tokenSecret) content = Signature $ signature signatureMethod
  where
    signature HMAC_SHA1 = B64.encode $ BL.toStrict $ bytestringDigest $ hmacSha1 (BL.fromStrict key) (BL.fromStrict content)
    signature Plaintext = key
    -- RSA_SHA1 not supported at this point
    -- signature RSA_SHA1  = undefined
    key = concatParamStrings [consSecret, tokenSecret]

genSignatureBase :: RequestMethod -> NormalizedURL -> ByteString -> ByteString
genSignatureBase method normUrl params = concatParamStrings [method, normUrl, params]

concatParamStrings :: [ByteString] -> ByteString
concatParamStrings = B.intercalate "&" . map oauthEncodeString

genParamString :: SimpleQueryText -> ByteString
genParamString params = E.encodeUtf8 $ T.intercalate "&" paramPairs
  where
    sortedParams = sort params
    paramPairs = [T.concat [oauthEncode k,"=",oauthEncode v] | (k,v) <- sortedParams]

generateNormUrl :: Request -> Either OAuthError ByteString
generateNormUrl request =
    let secure = isSecure request
        scheme = if secure then "https" else "http"
        hostport = fmap (B.break (58 ==)) (requestHeaderHost request)
        mkPort port = case port of
            ":80" -> if not secure then "" else port
            ":443" -> if secure then "" else port
            p -> p
        path = T.intercalate "/" $ pathInfo request
    in note MissingHostHeader $ do
        (host, port) <- hostport
        return $ B.concat [scheme, "://", host, mkPort port, "/", E.encodeUtf8 path]

splitOAuthParams :: MonadIO m => OAuthM m (SimpleQueryText, SimpleQueryText)
splitOAuthParams = do
    req <- get
    formBody <- formBodyParameters
    oauthEither $ tryInOrder (authHeaderParams req) formBody (query req)
  where
    authHeaderParams req = fromMaybe [] $ (maybeResult . parse parseAuthHeader) =<< lookup "Authentication" (requestHeaders req)

tryInOrder :: SimpleQueryText -> SimpleQueryText -> SimpleQueryText -> Either OAuthError (SimpleQueryText, SimpleQueryText)
tryInOrder authParams bodyParams queryParams =
    case (hasParams authParams, hasParams bodyParams, hasParams queryParams) of
        (True, False, False)  -> extractParams authParams bodyParams queryParams
        (False, True, False)  -> extractParams bodyParams queryParams authParams
        (False, False, True)  -> extractParams queryParams authParams bodyParams
        (False, False, False) -> Left $ MissingParameter "oauth_consumer_key"
        _                     -> Left MultipleOAuthParamLocations
  where
    hasParams = any isOAuthParam
    extractParams as bs cs = let (oauths, rest) = partition isOAuthParam as
                             in  fmap (, rest ++ bs ++ cs) $ findErrors oauths
    isOAuthParam = T.isPrefixOf "oauth_" . fst
    findErrors :: SimpleQueryText -> Either OAuthError SimpleQueryText
    findErrors oauths = let xs = group . sort $ map fst oauths
                            duplicate = fmap (Left . DuplicateParameter . head) $ find ((> 1) . length) xs
                            unsupported = fmap (Left . UnsupportedParameter . fst) $ find (flip notElem oauthParamNames . fst) oauths
                        in  fromMaybe (Right oauths) $ unsupported <|> duplicate

formBodyParameters :: MonadIO m => OAuthM m SimpleQueryText
formBodyParameters = do
    req <- get
    case getRequestBodyType req of
        Just UrlEncoded -> do
            (body, replayedBody) <- liftIO $ replay req
            let req' = req { requestBody = replayedBody }
                params = parseSimpleQuery $ mconcat body
                result = [(E.decodeUtf8 k, E.decodeUtf8 v) | (k, v) <- params]
            modify (const req')
            return result
        _               -> return []
  where
    replay req = do
        body <- requestBody req C.$$ CL.consume
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

oauthEither :: Monad m => Either OAuthError b -> OAuthM m b
oauthEither = OAuthT . hoistEither

liftOAuthT :: Monad m => m a -> OAuthT r s m a
liftOAuthT = OAuthT . lift .lift . lift

extractSignatureMethod :: ByteString -> Either OAuthError SignatureMethod
extractSignatureMethod "HMAC-SHA1" = Right HMAC_SHA1
extractSignatureMethod "PLAINTEXT" = Right Plaintext
-- wai-oauth doesn't support RSA-SHA1 at this point
-- extractSignatureMethod "RSA-SHA1"  = Right RSA_SHA1
extractSignatureMethod method      = Left $ UnsupportedSignatureMethod method

parseAuthHeader :: Parser SimpleQueryText
parseAuthHeader = do
    string "OAuth"
    skipSpace
    sepBy (mfilter (T.isPrefixOf "oauth_" . fst) lineParser) separator
  where
    separator = do
        char ','
        skipSpace

lineParser :: Parser (Text, Text)
lineParser = do
        key <- takeTill ('=' ==)
        value <- "=\"" .*> takeTill ('"' ==) <*. "\""
        return (E.decodeUtf8 $ urlDecode True key, E.decodeUtf8 $ urlDecode True value)

oauthParamNames :: [Text]
oauthParamNames = map (T.append "oauth_") ["consumer_key", "callback", "token", "nonce", "timestamp", "signature_method", "signature", "verifier", "version"]

oauthEncode :: Text -> Text
oauthEncode = T.concatMap enc
  where
    enc c
        | isAscii c && (isAlpha c || isDigit c || c `elem` "-._~") = T.singleton c
        | otherwise = let num = (grouped 2 . B16.encode . E.encodeUtf8 . T.singleton) c
                          hex = B.concat $ map (B.append "%") num
                      in T.toUpper $ E.decodeUtf8 hex


oauthEncodeString :: ByteString -> ByteString
oauthEncodeString = E.encodeUtf8 . oauthEncode . E.decodeUtf8

grouped :: Int -> ByteString -> [ByteString]
grouped n as = if B.null as then [] else result
  where
    (str, rest) = B.splitAt n as
    result = str : grouped n rest

query :: Request -> SimpleQueryText
query = fmap (second (fromMaybe "")) . queryToQueryText . queryString

debug :: Show a => a -> a
debug a = traceShow a a
