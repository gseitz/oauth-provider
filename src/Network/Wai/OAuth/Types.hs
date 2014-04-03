{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
module Network.Wai.OAuth.Types where

import           Control.Applicative        (Applicative)
import           Control.Concurrent.MonadIO (MonadIO)
import           Control.Monad.Reader       (MonadReader (..))
import           Control.Monad.State        (MonadState, get, put)
import           Control.Monad.Trans        (MonadTrans, lift)
import           Control.Monad.Trans.Either (EitherT)
import           Control.Monad.Trans.Reader (ReaderT)
import           Control.Monad.Trans.State  (StateT (..))
import           Data.ByteString            (ByteString)
import           Data.Int                   (Int64)
import           Data.Text                  (Text)
import           Network.Wai                (Request)

data SignatureMethod = HMAC_SHA1 | RSA_SHA1 | Plaintext deriving (Show, Enum)

data TokenType = AccessToken | RequestToken deriving (Show, Eq)

newtype ConsumerKey = ConsumerKey { unConsumerKey :: ByteString } deriving (Eq, Show)

newtype RequestTokenKey = RequestTokenKey { unRequestTokenKey :: ByteString } deriving (Eq, Show)
newtype AccessTokenKey = AccessTokenKey { unAccessTokenKey :: ByteString } deriving (Eq, Show)

newtype Verifier = Verifier { unVerifier :: ByteString } deriving (Eq, Show)

newtype Callback = Callback { unCallback :: ByteString } deriving (Eq, Show)

newtype Nonce = Nonce { unNonce :: ByteString } deriving (Eq, Show)
newtype Signature = Signature { unSignature :: ByteString } deriving (Eq, Show)

data OAuthParams = OAuthParams {
    opConsumerKey     :: ConsumerKey,
    opToken           :: ByteString,
    opSignatureMethod :: SignatureMethod,
    opCallback        :: Maybe Callback,
    opVerifier        :: Maybe Verifier,
    opSignature       :: Signature,
    opNonce           :: Maybe Nonce,
    opTimestamp       :: Maybe Integer
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


type SimpleQueryText = [(Text, Text)]
type RequestMethod = ByteString
type NormalizedURL = ByteString
type ParamString = ByteString
type ConsumerSecret = ByteString
type TokenSecret = ByteString
type Secrets = (ConsumerSecret, TokenSecret)
type Timestamp = Int64
type PathPart = [Text]


newtype OAuthT r s m a = OAuthT { runOAuthT :: EitherT OAuthError (StateT s (ReaderT r m)) a } deriving (Functor, Applicative, Monad, MonadIO)
type OAuthM m a = OAuthT (OAuthConfig m) Request m  a

instance Monad m => MonadState s (OAuthT r s m) where
    get = OAuthT get
    put s = OAuthT $ put s

instance Monad m => MonadReader r (OAuthT r s m) where
    ask = OAuthT ask
    local f r = OAuthT . local f $ runOAuthT r

instance MonadTrans (OAuthT r s) where
    lift = OAuthT . lift . lift . lift

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

twoLeggedConfig :: Monad m => SecretLookup ConsumerKey  m -> SecretLookup AccessTokenKey m -> SecretLookup RequestTokenKey m -> TokenGenerator m -> NonceTimestampCheck m -> [SignatureMethod] -> OAuthConfig m
twoLeggedConfig cons acc req tokenGen check methods = OAuthConfig cons acc req tokenGen check methods emptyCallbackLookup emptyVerifierLookup

threeLeggedConfig :: Monad m => SecretLookup ConsumerKey m -> SecretLookup AccessTokenKey m -> SecretLookup RequestTokenKey m -> TokenGenerator m -> NonceTimestampCheck m -> [SignatureMethod] -> CallbackLookup m -> VerifierLookup m -> OAuthConfig m
threeLeggedConfig = OAuthConfig

emptyVerifierLookup :: Monad m => VerifierLookup m
emptyVerifierLookup = const . return . Verifier $ ""

emptyCallbackLookup :: Monad m => CallbackLookup m
emptyCallbackLookup = const . return . Callback $ ""

emptyTokenLookup :: Monad m => SecretLookup t m
emptyTokenLookup = const (return $ Right "")

bsSecretLookup :: Monad m => (ByteString -> t) -> SecretLookup t m -> SecretLookup ByteString m
bsSecretLookup f l = l . f

data OAuthState = OAuthState
    { oauthRawParams :: SimpleQueryText
    , reqParams      :: SimpleQueryText
    , reqUrl         :: ByteString
    , reqMethod      :: ByteString
    , oauthParams    :: OAuthParams
    }

type SecretLookup k m = k -> m (Either OAuthError ByteString)
type Lookup t m  = (ConsumerKey, ByteString) -> m t
type VerifierLookup m = Lookup Verifier m
type CallbackLookup m = Lookup Callback m
type NonceTimestampCheck m = OAuthParams -> m (Maybe OAuthError)
type TokenGenerator m = TokenType -> ConsumerKey -> m (ByteString, ByteString)
