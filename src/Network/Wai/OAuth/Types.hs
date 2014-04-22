{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}

module Network.Wai.OAuth.Types
    (
      SignatureMethod(..)
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
    , OAuthT(OAuthT)
    , OAuthM
    , runOAuth
    ) where

import           Control.Applicative        (Applicative)
import           Control.Concurrent.MonadIO (MonadIO)
import           Control.Monad.Reader       (MonadReader (..))
import           Control.Monad.State        (MonadState, get, put)
import           Control.Monad.Trans        (MonadTrans, lift)
import           Control.Monad.Trans.Either (EitherT, runEitherT)
import           Control.Monad.Trans.Reader (ReaderT, runReaderT)
import           Control.Monad.Trans.State  (StateT (..), runStateT)
import           Data.ByteString            (ByteString)
import           Data.Int                   (Int64)
import           Data.String                (IsString)
import           Data.Text                  (Text)
import           Network.HTTP.Types         (badRequest400, unauthorized401)
import           Network.Wai                (Request, Response, responseLBS)

import qualified Data.ByteString.Lazy       as BL
import qualified Data.Text                  as T
import qualified Data.Text.Encoding         as E


-- | Supported signature methods. /RSA-SHA1/ is currently not supported.
data SignatureMethod = HMAC_SHA1 -- ^ <http://tools.ietf.org/html/rfc5849#section-3.4.2 RFC5849#3.4.2>
                     | Plaintext -- ^ <http://tools.ietf.org/html/rfc5849#section-3.4.4 RFC5849#3.4.4>
                     {-- RSA_SHA1  -- not supported at this point --}
                     deriving (Show, Enum, Eq)

data TokenType = AccessToken | RequestToken deriving (Show, Eq)

newtype ConsumerKey = ConsumerKey ByteString deriving (Eq, Show)
newtype AccessTokenKey = AccessTokenKey { unAccessTokenKey :: ByteString } deriving (Eq, Show, IsString)
newtype RequestTokenKey = RequestTokenKey { unRequestTokenKey :: ByteString } deriving (Eq, Show, IsString)

newtype Verifier = Verifier ByteString deriving (Eq, Show, IsString)
newtype Callback = Callback ByteString deriving (Eq, Show, IsString)

newtype Nonce = Nonce ByteString deriving (Eq, Show)
newtype Signature = Signature ByteString deriving (Eq, Show)

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
-- different kind of requests as part of the one legged, two legged, or
-- three legged flows.
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

-- | Constructs an 'OAuthConfig' value for the one legged flow.
oneLeggedConfig :: Monad m =>
    SecretLookup ConsumerKey m -- ^ Monadic value to lookup the secret associated
                               -- with the given 'ConsumerKey'.
    -> NonceTimestampCheck m -- ^ A check to verify that the combination of
                             -- 'ConsumerKey', 'Token', 'Nonce', and
                             -- 'Timestamp' hasn't been used before.
    -> [SignatureMethod] -- ^ The supported 'SignatureMethod's.
    -> OAuthConfig m
oneLeggedConfig consumerLookup check methods =
    OAuthConfig consumerLookup (requireEmptyTokenLookup . unAccessTokenKey)
                (requireEmptyTokenLookup . unRequestTokenKey)
                emptyTokenGen check methods noopCallbackStore emptyVerifierLookup
  where
    emptyTokenGen _ = const (return ("",""))

-- | Constructs an 'OAuthConfig' value for the two legged flow.
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

-- | Constructs an 'OAuthConfig' value for the three legged flow.
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

newtype Token = Token { unToken :: ByteString } deriving (Show, Eq, IsString)
newtype Secret = Secret ByteString deriving (Show, Eq, IsString)

type SimpleQueryText = [(Text, Text)]
type RequestMethod = ByteString
type NormalizedURL = ByteString
type ConsumerSecret = Secret
type TokenSecret = Secret
type Secrets = (ConsumerSecret, TokenSecret)
type Timestamp = Int64
type PathParts = [Text]
type VerifierLookup m  = (ConsumerKey, Token) -> m Verifier
type CallbackStore m = (ConsumerKey, Token) -> Callback -> m ()
type NonceTimestampCheck m = OAuthParams -> m (Maybe OAuthError)
-- | Action that generates a key and secret associated to the 'ConsumerKey' for the given 'TokenType'
type TokenGenerator m = TokenType -> ConsumerKey -> m (Token, Secret)

type SecretLookup k m = k -> m (Either OAuthError Secret)
type ConsumerSecretLookup m = SecretLookup ConsumerKey m
type AccessSecretLookup m = SecretLookup AccessTokenKey m
type RequestSecretLookup m = SecretLookup RequestTokenKey m

newtype OAuthT r s m a = OAuthT { runOAuthT :: EitherT OAuthError (StateT s (ReaderT r m)) a }
    deriving (Functor, Applicative, Monad, MonadIO)
type OAuthM m a = OAuthT (OAuthConfig m) Request m  a

runOAuth :: Monad m => r -> s -> OAuthT r s m a -> m (Either OAuthError a, s)
runOAuth config req = (`runReaderT` config) . (`runStateT` req) . runEitherT . runOAuthT

instance Monad m => MonadState s (OAuthT r s m) where
    get = OAuthT get
    put s = OAuthT $ put s

instance Monad m => MonadReader r (OAuthT r s m) where
    ask = OAuthT ask
    local f r = OAuthT . local f $ runOAuthT r

instance MonadTrans (OAuthT r s) where
    lift = OAuthT . lift . lift . lift


emptyVerifierLookup :: Monad m => VerifierLookup m
emptyVerifierLookup = const . return . Verifier $ ""

noopCallbackStore :: Monad m => CallbackStore m
noopCallbackStore = const . const $ return ()

emptyTokenLookup :: (Monad m, Eq t, IsString t) => SecretLookup t m
emptyTokenLookup "" = return $ Right ""
emptyTokenLookup _ = return . Left $ InvalidToken ""

requireEmptyTokenLookup :: Monad m => SecretLookup ByteString m
requireEmptyTokenLookup "" = return . Right $ ""
requireEmptyTokenLookup t  = return . Left . InvalidToken $ t


