{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE DeriveGeneric              #-}

module Network.OAuth.Provider.OAuth1.Types
    (
      OAuthRequest(..)
    , OAuthResponse(..)
    , SignatureMethod(..)
    , TokenType(..)
    , ConsumerKey(..)
    , RequestTokenKey(..)
    , AccessTokenKey(..)
    , Token(..)
    , Secret(..)
    , Verifier(..)
    , Callback(..)
    , Nonce(..)
    , Signature(..)
    , OAuthParams(..)
    , OAuthError(..)
    , UserId
    , errorAsResponse
    , emptyTokenLookup
    , noopCallbackStore

    -- * OAuth configuration
    , OAuthConfig(..)
    , oneLeggedConfig
    , twoLeggedConfig
    , threeLeggedConfig

    -- * Type aliases
    , SimpleQueryText
    , RequestMethod
    , NormalizedURL
    , ConsumerSecret
    , TokenSecret
    , Secrets
    , Timestamp
    , PathParts
    , SecretLookup
    , ConsumerSecretLookup
    , AccessSecretLookup
    , RequestSecretLookup
    , VerifierLookup
    , CallbackStore
    , NonceTimestampCheck
    , TokenGenerator

    -- * Monad
    , OAuthM(OAuthM)
    , runOAuth
    , getOAuthConfig
    , getOAuthRequest
    ) where

import           Control.Applicative        (Applicative)
import           Control.Monad.Reader       (MonadReader (..))
import           Control.Monad.Trans        (MonadTrans, lift)
import           Control.Monad.Trans.Either (EitherT, runEitherT)
import           Control.Monad.Trans.Reader (ReaderT, runReaderT)
import           Data.ByteString            (ByteString)
import           Data.Int                   (Int64)
import           Data.String                (IsString)
import           Data.Text                  (Text)
import           GHC.Generics
import           Network.HTTP.Types         (ResponseHeaders, Status,
                                             badRequest400, unauthorized401)

import qualified Data.Text                  as T
import qualified Data.Text.Encoding         as E


-- | 'OAuthRequest' is used to decouple oauth-provider from the underlying
-- representation of an HTTP requests of the various web frameworks.
-- This datatype contains all the necessary information for properly handling
-- OAuth requests.
data OAuthRequest = OAuthRequest
    { reqIsSecure             :: !Bool -- ^ Whether the request is made via https or not
    , reqPath                 :: ![Text] -- ^ The request path without the query string
    , reqQueryParams          :: !SimpleQueryText -- ^ The request parameters
    , reqBodyParams           :: !SimpleQueryText -- ^ The decoded parameters from the formbody
    , reqAuthenticationHeader :: !SimpleQueryText -- ^ The parsed Authentication header
    , reqHeaderHost           :: !Text -- ^ The host part of the Host header
    , reqHeaderPort           :: !Int -- ^ The port part of the Host header
    , reqRequestMethod        :: !ByteString -- ^ The value of the request method header
    } deriving (Eq, Show)

-- | 'OAuthResponse is used to decouple oauth-provider from the underlying
-- representation of an HTTP response of the various web frameworks.
-- This dataype contains the bare minimum information for creating an
-- actual response.
data OAuthResponse = OAuthResponse
    { respStatus  :: !Status -- ^ The HTTP 'Status' code of the response
    , respHeaders :: !ResponseHeaders -- ^ The HTTP response headers
    , respBody    :: !ByteString -- ^ The content of the response
    } deriving (Eq, Show)

-- | Supported signature methods. /RSA-SHA1/ is currently not supported.
data SignatureMethod = HMAC_SHA1 -- ^ <http://tools.ietf.org/html/rfc5849#section-3.4.2 RFC5849#3.4.2>
                     | Plaintext -- ^ <http://tools.ietf.org/html/rfc5849#section-3.4.4 RFC5849#3.4.4>
                     {-- RSA_SHA1  -- not supported at this point --}
                     deriving (Show, Enum, Eq)

data TokenType = AccessToken | RequestToken deriving (Show, Eq)

newtype ConsumerKey = ConsumerKey { unConsumerKey :: ByteString } deriving (Eq, Show)
newtype AccessTokenKey = AccessTokenKey { unAccessTokenKey :: ByteString } deriving (Eq, Show, IsString)
newtype RequestTokenKey = RequestTokenKey { unRequestTokenKey :: ByteString } deriving (Eq, Show, IsString)

newtype Verifier = Verifier ByteString deriving (Eq, Show, IsString)
newtype Callback = Callback ByteString deriving (Eq, Show, IsString)

newtype Nonce = Nonce { unNonce :: ByteString } deriving (Eq, Show)
newtype Signature = Signature { unSignature :: ByteString } deriving (Eq, Show)

-- | Captures all OAuth parameters in a request.
data OAuthParams = OAuthParams
    { opConsumerKey     :: !ConsumerKey
    , opToken           :: !Token
    , opSignatureMethod :: !SignatureMethod
    , opCallback        :: !(Maybe Callback)
    , opVerifier        :: !(Maybe Verifier)
    , opSignature       :: !Signature
    , opNonce           :: !(Maybe Nonce)
    , opTimestamp       :: !(Maybe Timestamp)
    } deriving Show

-- | 'OAuthError' represents the various errors that can occur when
-- processing OAuth requests.
data OAuthError = DuplicateParameter Text
                | UnsupportedParameter Text
                | MissingParameter Text
                | UnsupportedSignatureMethod ByteString
                | InvalidConsumerKey ByteString
                | InvalidToken ByteString
                | ExpiredToken ByteString
                | InvalidSignature Signature
                | InvalidTimestamp
                | UsedNonce
                | ExpiredRequest
                | MultipleOAuthParamLocations
                | MissingHostHeader
                | InvalidVerifier Verifier
                deriving (Show, Eq)

-- | 'OAuthConfig' captures everything that is need for the processing the
-- different kind of requests as part of the one-legged, two-legged, or
-- three-legged flows.
data OAuthConfig m = OAuthConfig
    { -- | A function to lookup the 'Secret' for the given 'ConsumerKey'.
      cfgConsumerSecretLookup      :: !(SecretLookup ConsumerKey m)
      -- | A function to lookup the 'Secret' for the given 'AccessTokenKey'.
    , cfgAccessTokenSecretLookup   :: !(SecretLookup AccessTokenKey m)
      -- | A function to lookup the 'Secret' for the give 'RequestTokenKey'.
    , cfgRequestTokenSecretLookup  :: !(SecretLookup RequestTokenKey m)
      -- | A function for generating a new token/secret pair of the given 'TokenType'.
      -- This function is also responsible to store the token/secret pair for later retrieval.
    , cfgTokenGenerator            :: !(TokenGenerator m)
      -- | A function that checks the uniqueness of the 'opNonce', 'opTimestamp',
      -- 'opConsumerKey', and 'opToken'.
    , cfgNonceTimestampCheck       :: !(NonceTimestampCheck m)
      -- | A list of 'SignatureMethod's the hosting application wants to provide.
    , cfgSupportedSignatureMethods :: !([SignatureMethod])
      -- | A function that stores the 'Callback' URL associated with the given
      -- 'ConsumerKey' and 'Token'.
    , cfgCallbackStore             :: !(CallbackStore m)
      -- | A function for looking up a previously stored 'Verifier' associated
      -- with the given 'ConsumerKey' and 'Token'.
    , cfgVerifierLookup            :: !(VerifierLookup m)
    }

-- | Constructs an 'OAuthConfig' value for the one-legged flow.
oneLeggedConfig :: Monad m =>
    SecretLookup ConsumerKey m -- ^ Monadic value to lookup the secret associated
                               -- with the given 'ConsumerKey'.
    -> NonceTimestampCheck m -- ^ A check to verify that the combination of
                             -- 'ConsumerKey', 'Token', 'Nonce', and
                             -- 'Timestamp' hasn't been used before.
    -> [SignatureMethod] -- ^ The supported 'SignatureMethod's.
    -> OAuthConfig m
oneLeggedConfig consumerLookup check methods =
    OAuthConfig consumerLookup (emptyTokenLookup . unAccessTokenKey)
                (emptyTokenLookup . unRequestTokenKey)
                emptyTokenGen check methods noopCallbackStore emptyVerifierLookup
  where
    emptyTokenGen = const . const $ return ("","")

-- | Constructs an 'OAuthConfig' value for the two-legged flow.
twoLeggedConfig :: Monad m =>
    ConsumerSecretLookup m -- ^ Monadic value to lookup the secret associated
                           -- with the given 'ConsumerKey'.
    -> AccessSecretLookup m -- ^ Monadic value to lookup the secret associated
                            -- with the given 'AccessTokenKey'.
    -> RequestSecretLookup m -- ^ Monadic value to lookup the secret associated
                             -- with the given 'RequestTokenKey'.
    -> TokenGenerator m -- ^ Monadic value for generating a new 'Token'/'Secret'
                        -- for the given 'TokenType' and 'ConsumerKey'.
    -> NonceTimestampCheck m -- ^ A check to verify that the combination of
                             -- 'ConsumerKey', 'Token', 'Nonce', and
                             -- 'Timestamp' hasn't been used before.
    -> [SignatureMethod] -- ^ The supported 'SignatureMethod's.
    -> OAuthConfig m
twoLeggedConfig cons acc req tokenGen check methods =
    OAuthConfig cons acc req tokenGen check
        methods noopCallbackStore emptyVerifierLookup

-- | Constructs an 'OAuthConfig' value for the three-legged flow.
threeLeggedConfig :: Monad m =>
    ConsumerSecretLookup m -- ^ Monadic value to lookup the secret associated
                           -- with the given 'ConsumerKey'.
    -> AccessSecretLookup m -- ^ Monadic value to lookup the secret associated
                            -- with the given 'AccessTokenKey'.
    -> RequestSecretLookup m -- ^ Monadic value to lookup the secret associated
                             -- with the given 'RequestTokenKey'.
    -> TokenGenerator m -- ^ Monadic value for generating a new 'Token'/'Secret'
                        -- for the given 'TokenType' and 'ConsumerKey'.
    -> NonceTimestampCheck m -- ^ A check to verify that the combination of
                             -- 'ConsumerKey', 'Token', 'Nonce', and
                             -- 'Timestamp' hasn't been used before.
    -> [SignatureMethod] -- ^ The supported 'SignatureMethod's.
    -> CallbackStore m -- ^ Monadic value to look up a previously stored
                        -- 'Callback' URL
    -> VerifierLookup m -- ^ Monadic value to lookup a previously stored
                        -- 'Verifier' token.
    -> OAuthConfig m
threeLeggedConfig = OAuthConfig

-- | Builds an 'OAuthResponse' out of an 'OAuthError' and sets the appropriate
-- 'Status' code.
errorAsResponse :: OAuthError -> OAuthResponse
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
    resp status = OAuthResponse status [] $ E.encodeUtf8 $ T.pack $ show err

newtype Token = Token { unToken :: ByteString }
  deriving (Show, Eq, IsString, Generic)
newtype Secret = Secret { unSecret :: ByteString }
  deriving (Show, Eq, IsString, Generic)

type SimpleQueryText = [(Text, Text)]
type RequestMethod = ByteString
type NormalizedURL = ByteString
type UserId = ByteString
type ConsumerSecret = Secret
type TokenSecret = Secret
type Secrets = (ConsumerSecret, TokenSecret)
type Timestamp = Int64
type PathParts = [Text]
type VerifierLookup m  = (ConsumerKey, RequestTokenKey) -> m (Verifier, UserId)
type CallbackStore m = (ConsumerKey, RequestTokenKey) -> Callback -> m ()
type NonceTimestampCheck m = OAuthParams -> m (Maybe OAuthError)
-- | Action that generates a key and secret associated to the 'ConsumerKey' for the given 'TokenType'
type TokenGenerator m = TokenType -> ConsumerKey -> m (Token, Secret)

type SecretLookup k m = k -> m (Either OAuthError Secret)
-- | Action to lookup the consumer secret.
type ConsumerSecretLookup m = SecretLookup ConsumerKey m
-- | Action to lookup the access token secret.
type AccessSecretLookup m = SecretLookup AccessTokenKey m
-- | Action to lookup the request token secret.
type RequestSecretLookup m = SecretLookup RequestTokenKey m

-- | The monad transformer in which all the OAuth operations are running.
newtype OAuthM m a = OAuthM { runOAuthM :: EitherT OAuthError (ReaderT (OAuthConfig m, OAuthRequest) m) a }
    deriving (Functor, Applicative, Monad)

runOAuth :: Monad m => (OAuthConfig m, OAuthRequest) -> OAuthM m a -> m (Either OAuthError a)
runOAuth config = (`runReaderT` config) . runEitherT . runOAuthM

instance Monad m => MonadReader (OAuthConfig m, OAuthRequest) (OAuthM m) where
    ask = OAuthM ask
    local f r = OAuthM . local f $ runOAuthM r

instance MonadTrans OAuthM where
    lift = OAuthM . lift . lift


-- | Convenience function to get the 'OAuthRequest' out of the 'ReaderT' slice of the stack.
getOAuthRequest :: Monad m => OAuthM m OAuthRequest
getOAuthRequest = fmap snd ask

-- | Convenience function to get the 'OAuthConfig' out of the 'ReaderT' slice of the stack.
getOAuthConfig :: Monad m => OAuthM m (OAuthConfig m)
getOAuthConfig = fmap fst ask

-- | Convenience function that always returns an empty 'Verifier'.
-- This function is only used in the one-legged and two-legged flow, as no
-- verifier is involved there.
emptyVerifierLookup :: Monad m => VerifierLookup m
emptyVerifierLookup = const $ return (Verifier "", "")

noopCallbackStore :: Monad m => CallbackStore m
noopCallbackStore = const . const $ return ()

-- | Constructs a 'SecretLookup' that only succeeds if the input 'Token' is empty.
emptyTokenLookup :: (Monad m, Eq t, IsString t) => SecretLookup t m
emptyTokenLookup "" = return $ Right ""
emptyTokenLookup _ = return . Left $ InvalidToken "<non-empty token>"

