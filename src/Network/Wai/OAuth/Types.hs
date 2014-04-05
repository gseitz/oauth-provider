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
    , runOAuthM
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

data SignatureMethod = HMAC_SHA1
                     | Plaintext
                     {- | RSA_SHA1  -- not supported at this point-}
                     deriving (Show, Enum, Eq)

data TokenType = AccessToken | RequestToken deriving (Show, Eq)

newtype ConsumerKey = ConsumerKey ByteString deriving (Eq, Show)
newtype RequestTokenKey = RequestTokenKey ByteString deriving (Eq, Show)
newtype AccessTokenKey = AccessTokenKey ByteString deriving (Eq, Show)

newtype Verifier = Verifier ByteString deriving (Eq, Show)
newtype Callback = Callback ByteString deriving (Eq, Show)

newtype Nonce = Nonce ByteString deriving (Eq, Show)
newtype Signature = Signature ByteString deriving (Eq, Show)

data OAuthParams = OAuthParams {
    opConsumerKey     :: ConsumerKey,
    opToken           :: ByteString,
    opSignatureMethod :: SignatureMethod,
    opCallback        :: Maybe Callback,
    opVerifier        :: Maybe Verifier,
    opSignature       :: Signature,
    opNonce           :: Maybe Nonce,
    opTimestamp       :: Maybe Timestamp
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
    { cfgConsumerSecretLookup      :: SecretLookup ConsumerKey m
    , cfgAccessTokenSecretLookup   :: SecretLookup AccessTokenKey m
    , cfgRequestTokenSecretLookup  :: SecretLookup RequestTokenKey m
    , cfgTokenGenerator            :: TokenGenerator m
    , cfgNonceTimestampCheck       :: NonceTimestampCheck m
    , cfgSupportedSignatureMethods :: [SignatureMethod]
    , cfgCallbackLookup            :: CallbackLookup m
    , cfgVerifierLookup            :: VerifierLookup m
    }

oneLeggedConfig :: Monad m => SecretLookup ConsumerKey m -> NonceTimestampCheck m -> [SignatureMethod] -> OAuthConfig m
oneLeggedConfig consumerLookup check methods = OAuthConfig consumerLookup emptyTokenLookup emptyTokenLookup emptyTokenGen check methods emptyCallbackLookup emptyVerifierLookup
  where
    emptyTokenGen _ = const (return ("",""))

twoLeggedConfig :: Monad m => ConsumerSecretLookup m -> AccessSecretLookup m -> RequestSecretLookup m -> TokenGenerator m -> NonceTimestampCheck m -> [SignatureMethod] -> OAuthConfig m
twoLeggedConfig cons acc req tokenGen check methods = OAuthConfig cons acc req tokenGen check methods emptyCallbackLookup emptyVerifierLookup

threeLeggedConfig :: Monad m => ConsumerSecretLookup m -> AccessSecretLookup m -> RequestSecretLookup m -> TokenGenerator m -> NonceTimestampCheck m -> [SignatureMethod] -> CallbackLookup m -> VerifierLookup m -> OAuthConfig m
threeLeggedConfig = OAuthConfig

newtype Token = Token ByteString deriving (Show, Eq, IsString)
newtype Secret = Secret ByteString deriving (Show, Eq, IsString)

type SimpleQueryText = [(Text, Text)]
type RequestMethod = ByteString
type NormalizedURL = ByteString
type ConsumerSecret = Secret
type TokenSecret = Secret
type Secrets = (ConsumerSecret, TokenSecret)
type Timestamp = Int64
type PathParts = [Text]
type Lookup t m  = (ConsumerKey, ByteString) -> m t
type VerifierLookup m = Lookup Verifier m
type CallbackLookup m = Lookup Callback m
type NonceTimestampCheck m = OAuthParams -> m (Maybe OAuthError)
type TokenGenerator m = TokenType -> ConsumerKey -> m (Token, Secret)

type SecretLookup k m = k -> m (Either OAuthError Secret)
type ConsumerSecretLookup m = SecretLookup ConsumerKey m
type AccessSecretLookup m = SecretLookup AccessTokenKey m
type RequestSecretLookup m = SecretLookup RequestTokenKey m

newtype OAuthT r s m a = OAuthT { runOAuthT :: EitherT OAuthError (StateT s (ReaderT r m)) a } deriving (Functor, Applicative, Monad, MonadIO)
type OAuthM m a = OAuthT (OAuthConfig m) Request m  a

runOAuthM :: Monad m => OAuthConfig m -> Request -> OAuthM m a -> m (Either OAuthError a, Request)
runOAuthM config req = (`runReaderT` config) . (`runStateT` req) . runEitherT . runOAuthT

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


