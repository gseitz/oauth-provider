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
    , emptyTokenLookup

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
    , Lookup
    , VerifierLookup
    , CallbackLookup
    , NonceTimestampCheck
    , TokenGenerator

    -- * Monad
    , OAuthT(..)
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
import           Network.Wai                (Request)


-- | Supported signature methods. /RSA-SHA1/ is currently not supported.
data SignatureMethod = HMAC_SHA1 -- ^ <http://tools.ietf.org/html/rfc5849#section-3.4.2 RFC5849#3.4.2>
                     | Plaintext -- ^ <http://tools.ietf.org/html/rfc5849#section-3.4.4 RFC5849#3.4.4>
                     {-- RSA_SHA1  -- not supported at this point --}
                     deriving (Show, Enum, Eq)

data TokenType = AccessToken | RequestToken deriving (Show, Eq)

newtype ConsumerKey = ConsumerKey ByteString deriving (Eq, Show)
newtype AccessTokenKey = AccessTokenKey { unAccessTokenKey :: ByteString } deriving (Eq, Show)
newtype RequestTokenKey = RequestTokenKey { unRequestTokenKey :: ByteString } deriving (Eq, Show)

newtype Verifier = Verifier ByteString deriving (Eq, Show)
newtype Callback = Callback ByteString deriving (Eq, Show)

newtype Nonce = Nonce ByteString deriving (Eq, Show)
newtype Signature = Signature ByteString deriving (Eq, Show)

-- | Captures all OAuth parameters in a request.
data OAuthParams = OAuthParams {
    opConsumerKey     :: !ConsumerKey,
    opToken           :: !Token,
    opSignatureMethod :: !SignatureMethod,
    opCallback        :: !(Maybe Callback),
    opVerifier        :: !(Maybe Verifier),
    opSignature       :: !Signature,
    opNonce           :: !(Maybe Nonce),
    opTimestamp       :: !(Maybe Timestamp)
    } deriving Show

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

data OAuthConfig m = OAuthConfig
    { cfgConsumerSecretLookup      :: !(SecretLookup ConsumerKey m)
    , cfgAccessTokenSecretLookup   :: !(SecretLookup AccessTokenKey m)
    , cfgRequestTokenSecretLookup  :: !(SecretLookup RequestTokenKey m)
    , cfgTokenGenerator            :: !(TokenGenerator m)
    , cfgNonceTimestampCheck       :: !(NonceTimestampCheck m)
    , cfgSupportedSignatureMethods :: !([SignatureMethod])
    , cfgCallbackLookup            :: !(CallbackLookup m)
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
                emptyTokenGen check methods emptyCallbackLookup emptyVerifierLookup
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
        methods emptyCallbackLookup emptyVerifierLookup

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
    -> CallbackLookup m -- ^ Monadic value to look up a previously stored
                        -- 'Callback' URL
    -> VerifierLookup m -- ^ Monadic value to lookup a previously stored
                        -- 'Verifier' token.
    -> OAuthConfig m
threeLeggedConfig = OAuthConfig

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
type Lookup t m  = (ConsumerKey, Token) -> m t
type VerifierLookup m = Lookup Verifier m
type CallbackLookup m = Lookup Callback m
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

emptyCallbackLookup :: Monad m => CallbackLookup m
emptyCallbackLookup = const . return . Callback $ ""

emptyTokenLookup :: Monad m => SecretLookup t m
emptyTokenLookup = const (return $ Right "")

requireEmptyTokenLookup :: Monad m => SecretLookup ByteString m
requireEmptyTokenLookup "" = return . Right $ ""
requireEmptyTokenLookup t  = return . Left . InvalidToken $ t


