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

data OAuthRequestType = OneLegged
                      | TwoLeggedRequest | TwoLeggedToken
                      | ThreeLeggedRequest | ThreeLeggedAuthorize | ThreeLeggedToken
                      deriving Show

data OAuthParams = OAuthParams {
    opConsumerKey     :: ByteString,
    opToken           :: ByteString,
    opSignatureMethod :: SignatureMethod,
    opCallback        :: Maybe ByteString,
    opVerifier        :: Maybe ByteString,
    opSignature       :: ByteString,
    opNonce           :: Maybe ByteString,
    opTimestamp       :: Maybe Integer
    } deriving Show

data OAuthError = DuplicateParameter Text
                | UnsupportedParameter Text
                | MissingParameter Text
                | UnsupportedSignatureMethod ByteString
                | InvalidConsumerKey ByteString
                | InvalidToken ByteString
                | ExpiredToken ByteString
                | InvalidSignature ByteString
                | UsedNonce ByteString
                | MultipleOAuthParamLocations
                | MissingHostHeader
                | InvalidVerifier ByteString
                deriving (Show, Eq)


type SimpleQueryText = [(Text, Text)]
type RequestMethod = ByteString
type NormalizedURL = ByteString
type ParamString = ByteString
type ConsumerSecret = ByteString
type TokenSecret = ByteString
type Secrets = (ConsumerSecret, TokenSecret)
type Nonce = ByteString
type Timestamp = Int64


newtype OAuthT r s m a = OAuthT { runOAuthT :: StateT s (EitherT OAuthError (ReaderT r m)) a } deriving (Functor, Applicative, Monad, MonadIO)
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
    { cfgConsumerSecretLookup      :: SecretLookup m
    , cfgAccessTokenSecretLookup   :: SecretLookup m
    , cfgRequestTokenSecretLookup  :: SecretLookup m
    , cfgTokenGenerator            :: TokenGenerator m
    , cfgNonceTimestampCheck       :: NonceTimestampCheck m
    , cfgSupportedSignatureMethods :: [SignatureMethod]
    , cfgCallbackLookup            :: CallbackLookup m
    , cfgVerifierLookup            :: VerifierLookup m
    }

oneLeggedConfig :: Monad m => SecretLookup m -> SecretLookup m -> NonceTimestampCheck m -> [SignatureMethod] -> OAuthConfig m
oneLeggedConfig consumerLookup tokenLookup check methods = OAuthConfig consumerLookup tokenLookup emptyToken (const (return ("", ""))) check methods emptyLookup emptyLookup
  where
    emptyToken tk = return $ Left (InvalidToken tk)

twoLeggedConfig :: Monad m => SecretLookup m -> SecretLookup m -> SecretLookup m -> NonceTimestampCheck m -> [SignatureMethod] -> OAuthConfig m
twoLeggedConfig cons acc req check methods = OAuthConfig cons acc req (const (return ("", ""))) check methods emptyLookup emptyLookup

threeLeggedConfig :: Monad m => SecretLookup m -> SecretLookup m -> SecretLookup m -> TokenGenerator m -> NonceTimestampCheck m -> [SignatureMethod] -> CallbackLookup m -> VerifierLookup m -> OAuthConfig m
threeLeggedConfig = OAuthConfig

emptyLookup :: Monad m => Lookup m
emptyLookup = const $ return ""

data OAuthState = OAuthState
    { oauthRawParams :: SimpleQueryText
    , reqParams      :: SimpleQueryText
    , reqUrl         :: ByteString
    , reqMethod      :: ByteString
    , oauthParams    :: OAuthParams
    }

type SecretLookup m = ByteString -> m (Either OAuthError ByteString)
type Lookup m = (ByteString, ByteString) -> m ByteString
type VerifierLookup m = Lookup m
type CallbackLookup m = Lookup m
type NonceTimestampCheck m = OAuthParams -> m (Maybe OAuthError)
type TokenGenerator m = ByteString -> m (ByteString, ByteString)
