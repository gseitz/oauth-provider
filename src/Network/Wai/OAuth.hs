{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE TupleSections              #-}

module Network.Wai.OAuth where

import           Control.Applicative        (Applicative, (<$>), (<*>), (<|>))
import           Control.Arrow              (second, (***))
import           Control.Concurrent.MonadIO (MonadIO, liftIO)
import           Control.Error.Util         (note)
import           Control.Monad              (join, mfilter)
import           Control.Monad.State
import           Control.Monad.Trans.Either
import           Data.Attoparsec.Char8      hiding (isDigit)
import           Data.ByteString            (ByteString)
import           Data.Char                  (isAlpha, isAscii, isDigit)
import           Data.Digest.Pure.SHA       (bytestringDigest, hmacSha1)
import           Data.Functor
import           Data.IORef.Lifted          (newIORef, readIORef, writeIORef)
import           Data.List                  (find, group, partition, sort)
import           Data.Maybe                 (fromMaybe, isJust)
import           Data.Monoid                (mconcat, (<>))
import           Data.Text                  (Text)
import           Network.HTTP.Types         (methodGet, parseSimpleQuery,
                                             queryToQueryText, urlDecode)
import           Network.Wai
import           Network.Wai.Parse          (RequestBodyType (..),
                                             getRequestBodyType, lbsBackEnd,
                                             parseRequestBody)

import           Debug.Trace

import qualified Data.ByteString            as B
import qualified Data.ByteString.Base16     as B16
import qualified Data.ByteString.Base64     as B64
import qualified Data.ByteString.Lazy       as BL
import qualified Data.Conduit               as C
import qualified Data.Conduit.Lazy          as CL
import qualified Data.Conduit.List          as CL
import qualified Data.Text                  as T
import qualified Data.Text.Encoding         as E

data OAuthRequestType = InitiateRequest | AuthorizeRequest | TokenRequest deriving (Show, Enum)

data SignatureMethod = HMAC_SHA1 | RSA_SHA1 | Plaintext deriving (Show, Enum)

data OAuthParams = OAuthParams {
    opConsumerKey     :: ByteString,
    opToken           :: ByteString,
    opSignatureMethod :: SignatureMethod,
    opCallback        :: Maybe ByteString,
    opSignature       :: ByteString,
    opNonce           :: ByteString,
    opTimestamp       :: ByteString
    } deriving Show

data OAuthKey = ConsumerKey ByteString | Token ByteString deriving Show

type SimpleQueryText = [(Text, Text)]
type RequestMethod = ByteString
type NormalizedURL = ByteString
type ParamString = ByteString
type ConsumerSecret = ByteString
type TokenSecret = ByteString
type Secrets = (ConsumerSecret, TokenSecret)

newtype OAuthT s m a = OAuthT { runOAuthT :: StateT s m a } deriving (Functor, Applicative, Monad, MonadIO)

instance Monad m => MonadState s (OAuthT s m) where
    get = OAuthT $ get
    put s = OAuthT $ put s

instance MonadTrans (OAuthT s) where
    lift = OAuthT . lift

data OAuthError = DuplicateParam Text
                | UnsupportedParameter Text
                | MissingParameter Text
                | UnsupportedSignatureMethod ByteString
                | InvalidConsumerKey ByteString
                | InvalidToken ByteString
                | ExpiredToken ByteString
                | InvalidSignature ByteString
                | UsedNonce ByteString
                | MultipleOAuthParamLocations
                deriving Show

data OAuthState = OAuthState
    { request        :: Request
    , oauthRawParams :: SimpleQueryText
    , reqParams         :: SimpleQueryText
    , reqMethod      :: ByteString
    , reqUrl            :: ByteString
    , oauthParams    :: OAuthParams
    }

query :: Request -> SimpleQueryText
query = fmap (second (fromMaybe "")) . queryToQueryText . queryString

type OAuthM m = OAuthT OAuthState (EitherT OAuthError m)

processRequest :: MonadIO m => OAuthM m ()
processRequest = do
    req <- gets request
    (oauths, rest) <- splitOAuthParams
    url <- generateNormUrl
    let get name = E.encodeUtf8 <$> lookup name oauths
        getE name = note (MissingParameter name) $ get name
        getOrEmpty name = fromMaybe "" $ get name
    oauth  <- lift $ hoistEither $ do
        signMeth <- getE "oauth_signature_method" >>= extractSignatureMethod
        signature <- getE "oauth_signature"
        consKey <- getE "oauth_consumer_key"
        token <- getE "oauth_token"
        return $ OAuthParams consKey token signMeth (get "oauth_callback") signature (getOrEmpty  "oauth_nonce") (getOrEmpty "oauth_timestamp")
    modify $ \s -> s { oauthRawParams = oauths, reqParams = rest, reqUrl = url, oauthParams = oauth }

verifyOAuthSignature :: (Functor m, MonadIO m) => (OAuthKey -> m (Either OAuthError ByteString)) -> OAuthM m ByteString
verifyOAuthSignature secretLookup = do
    OAuthState req oauthRaw rest method url oauth <- get
    secrets <- lift $ do
        cons <- EitherT . secretLookup . ConsumerKey $  opConsumerKey oauth
        token <- EitherT . secretLookup . Token $ opToken oauth
        return (cons, token)
    let cleanOAuths = filter ((/=) "oauth_signature" . fst) oauthRaw
    return $ genOAuthSignature oauth secrets method url (cleanOAuths <> rest)

genOAuthSignature :: OAuthParams -> Secrets -> RequestMethod -> NormalizedURL -> SimpleQueryText -> ByteString
genOAuthSignature oauthParams secrets method normUrl params = signature
  where
    signature = mkSignature (opSignatureMethod oauthParams) secrets baseString
    baseString = genSignatureBase method normUrl paramString
    paramString = genParamString params

mkSignature :: SignatureMethod -> Secrets -> ByteString -> ByteString
mkSignature signatureMethod (consSecret, tokenSecret) content = signature signatureMethod
  where
    signature HMAC_SHA1 = B64.encode $ BL.toStrict $ bytestringDigest $ hmacSha1 (BL.fromStrict key) (BL.fromStrict content)
    signature Plaintext = key
    signature RSA_SHA1  = undefined
    key = B.intercalate "&" $ map oauthEncodeString [consSecret, tokenSecret]

genSignatureBase :: RequestMethod -> NormalizedURL -> ByteString -> ByteString
genSignatureBase method normUrl params = B.intercalate "&" $ map oauthEncodeString [method, normUrl, params]

genParamString :: SimpleQueryText -> ByteString
genParamString params = E.encodeUtf8 $ T.intercalate "&" paramPairs
  where
    sortedParams = sort params
    paramPairs = [T.concat [oauthEncode k,"=",oauthEncode v] | (k,v) <- sortedParams]

generateNormUrl :: Monad m => OAuthM m ByteString
generateNormUrl = do
    req <- gets request
    let secure = isSecure req
        scheme = if secure then "https" else "http"
        hostport = fmap (B.break (58 ==)) (requestHeaderHost req)
        mkPort port = case port of
            ":80" -> if not secure then "" else port
            ":443" -> if secure then "" else port
            p -> p
        path = T.intercalate "/" $ pathInfo req
    lift $ hoistEither $ note (MissingParameter "Host header") $ do
        (host, p) <- hostport
        let port = mkPort p
        return $ B.concat [scheme, "://", host, port, "/", E.encodeUtf8 path]

splitOAuthParams :: MonadIO m => OAuthM m (SimpleQueryText, SimpleQueryText)
splitOAuthParams = do
    req <- gets request
    formBody <- formBodyParameters
    lift $ hoistEither $ tryInOrder (authHeaderParams req) formBody (query req)
  where
    authHeaderParams req = fromMaybe [] $ (maybeResult . parse parseAuthHeader) =<< lookup "Authentication" (requestHeaders req)

tryInOrder :: SimpleQueryText -> SimpleQueryText -> SimpleQueryText -> Either OAuthError (SimpleQueryText, SimpleQueryText)
tryInOrder authParams bodyParams queryParams =
    case (hasParams authParams, hasParams bodyParams, hasParams queryParams) of
        (True, False, False)  -> extractParams authParams bodyParams queryParams
        (False, True, False)  -> extractParams bodyParams queryParams authParams
        (False, False, True)  -> extractParams queryParams authParams bodyParams
        (False, False, False) -> Left $ MissingParameter "oauth_consumer_key"
        _                     -> Left $ MultipleOAuthParamLocations
  where
    hasParams = any isOAuthParam . debug
    extractParams as bs cs = let (oauths, rest) = partition isOAuthParam as
                             in  fmap (, rest ++ bs ++ cs) $ findErrors oauths
    isOAuthParam = (T.isPrefixOf "oauth_") . fst
    findErrors :: SimpleQueryText -> Either OAuthError SimpleQueryText
    findErrors oauths = let xs = group . sort $ map fst oauths
                            duplicate = fmap (Left . DuplicateParam . head) $ find ((>) 1 . length) xs
                            unsupported :: Maybe (Either OAuthError SimpleQueryText)
                            unsupported = fmap (Left . UnsupportedParameter . fst) $ find (flip notElem oauthParamNames . fst) oauths
                        in  fromMaybe (Right oauths) $ traceShow unsupported $ unsupported <|> duplicate

formBodyParameters :: MonadIO m => OAuthM m SimpleQueryText
formBodyParameters = do
    req <- gets request
    case getRequestBodyType req of
        Just UrlEncoded -> do
            (body, replayedBody) <- liftIO $ replay req
            let req' = req { requestBody = replayedBody }
                params = parseSimpleQuery $ mconcat body
                result = [(E.decodeUtf8 k, E.decodeUtf8 v) | (k, v) <- params]
            modify $ \s -> s { request = req' }
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


extractSignatureMethod :: ByteString -> Either OAuthError SignatureMethod
extractSignatureMethod "HMAC-SHA1" = Right HMAC_SHA1
extractSignatureMethod "RSA-SHA1"  = Right RSA_SHA1
extractSignatureMethod "PLAINTEXT" = Right Plaintext
extractSignatureMethod method      = Left $ UnsupportedSignatureMethod method

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
    (group, rest) = B.splitAt n as
    result = group : grouped n rest

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

both :: (b -> c) -> (b, b) -> (c, c)
both = join (***)



clientRequest :: Text -> Request
clientRequest x = defaultRequest {
    requestMethod = methodGet,
    requestHeaders = [("Host", "photos.example.net:80")],
    requestHeaderHost = Just "photos.example.net:80",
    pathInfo = ["photos"],
    queryString = [("oauth_consumer_key",Just "dpf43f3p2l4k3l03"),
        ("oauth_nonce",Just "kllo9940pd9333jh"),
        ("oauth_signature_method",Just "HMAC-SHA1"),
        ("oauth_timestamp",Just "1191242096"),
        ("oauth_token",Just "nnch734d00sl2jdk"),
        ("oauth_version",Just "1.0"),
        ("size", Just (B.append (E.encodeUtf8 x) "original")),
        ("file", Just "vacation.jpg"),
        ("oauth_signature", Just "tR3+Ty81lMeYAr/Fid0kMTYa/WM=")]
    }

debug :: Show a => a -> a
debug a = traceShow a a
