{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TupleSections     #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Network.OAuth.Provider.OAuth1.Internal where

import           Control.Applicative                 ((<$>), (<|>))
import           Control.Error.Util                  (note)
import           Control.Monad.Trans.Either          (hoistEither)
import           Data.ByteString                     (ByteString)
import           Data.Char                           (isAlpha, isAscii, isDigit)
import           Data.Digest.Pure.SHA                (bytestringDigest,
                                                      hmacSha1)
import           Data.List                           (find, group, partition,
                                                      sort)
import           Data.Maybe                          (fromMaybe)
import           Data.Text                           (Text)
import           Debug.Trace

import qualified Data.ByteString                     as B
import qualified Data.ByteString.Base16              as B16
import qualified Data.ByteString.Base64              as B64
import qualified Data.ByteString.Lazy                as BL
import qualified Data.Text                           as T
import qualified Data.Text.Encoding                  as E

import           Network.OAuth.Provider.OAuth1.Types

bsSecretLookup :: Monad m => (ByteString -> t) -> SecretLookup t m -> SecretLookup Token m
bsSecretLookup f l = l . f . unToken

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
mkSignature signatureMethod (Secret consSecret, Secret tokenSecret) content = Signature $ signature signatureMethod
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

generateNormUrl :: OAuthRequest -> Either OAuthError ByteString
generateNormUrl OAuthRequest{..} =
    let scheme = if reqIsSecure then "https" else "http"
        mkPort port = case port of
            80 -> if not reqIsSecure then "" else ":80"
            443 -> if reqIsSecure then "" else ":443"
            p -> E.encodeUtf8 $ T.pack $ ':' : show p
        path = T.intercalate "/" reqPath
    in note MissingHostHeader $
        return $ B.concat [scheme, "://", E.encodeUtf8 reqHeaderHost, mkPort reqHeaderPort, "/", E.encodeUtf8 path]

splitOAuthParams :: Monad m => OAuthM m (SimpleQueryText, SimpleQueryText)
splitOAuthParams = do
    req <- getOAuthRequest
    formBody <- formBodyParameters
    oauthEither $ validateAndExtractParams (reqAuthenticationHeader req) formBody (reqQueryParams req)

validateAndExtractParams :: SimpleQueryText -> SimpleQueryText -> SimpleQueryText -> Either OAuthError (SimpleQueryText, SimpleQueryText)
validateAndExtractParams authParams bodyParams queryParams =
    case (hasParams authParams, hasParams bodyParams, hasParams queryParams) of
        (True, False, False)  -> extractParams authParams bodyParams queryParams
        (False, True, False)  -> extractParams bodyParams queryParams authParams
        (False, False, True)  -> extractParams queryParams authParams bodyParams
        (False, False, False) -> Left $ MissingParameter "oauth_consumer_key" -- picking any of the always-mandatory parameters
        _                     -> Left MultipleOAuthParamLocations
  where
    hasParams = any isOAuthParam
    extractParams as bs cs = let (oauths, rest) = partition isOAuthParam as
                             in  (, rest ++ bs ++ cs) <$> findErrors oauths
    isOAuthParam = T.isPrefixOf "oauth_" . fst
    findErrors :: SimpleQueryText -> Either OAuthError SimpleQueryText
    findErrors oauths = let xs = group . sort $ map fst oauths
                            duplicate = (Left . DuplicateParameter . head) <$> find ((> 1) . length) xs
                            unsupported = (Left . UnsupportedParameter . fst) <$> find (flip notElem oauthParamNames . fst) oauths
                        in  fromMaybe (Right oauths) $ unsupported <|> duplicate

formBodyParameters :: Monad m => OAuthM m SimpleQueryText
formBodyParameters = fmap reqBodyParams getOAuthRequest

oauthEither :: Monad m => Either OAuthError b -> OAuthM m b
oauthEither = OAuthM . hoistEither

extractSignatureMethod :: ByteString -> Either OAuthError SignatureMethod
extractSignatureMethod "HMAC-SHA1" = Right HMAC_SHA1
extractSignatureMethod "PLAINTEXT" = Right Plaintext
-- oauth-provider doesn't support RSA-SHA1 at this point
-- extractSignatureMethod "RSA-SHA1"  = Right RSA_SHA1
extractSignatureMethod method      = Left $ UnsupportedSignatureMethod method


oauthParamNames :: [Text]
oauthParamNames = map (T.append "oauth_") ["consumer_key", "callback", "token", "nonce", "timestamp", "signature_method", "signature", "verifier", "version"]

oauthEncode :: Text -> Text
oauthEncode = T.concatMap enc
  where
    enc c
        | isAscii c && (isAlpha c || isDigit c || c `elem` ("-._~"::String)) = T.singleton c
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

debug :: Show a => a -> a
debug a = traceShow a a
