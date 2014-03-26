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
    opSignature       :: ByteString,
    opNonce           :: ByteString,
    opTimestamp       :: ByteString
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
    , cfgTokenGenerator            :: ByteString -> m (ByteString, ByteString)
    , cfgNonceTimestampCheck       :: NonceTimestampCheck m
    , cfgSupportedSignatureMethods :: [SignatureMethod]
    }

oneLeggedConfig :: Monad m => SecretLookup m -> SecretLookup m -> NonceTimestampCheck m -> [SignatureMethod] -> OAuthConfig m
oneLeggedConfig consumerLookup tokenLookup = OAuthConfig consumerLookup tokenLookup emptyToken $ const (return ("", ""))
  where
    emptyToken tk = return $ Left (InvalidToken tk)

twoLeggedConfig :: Monad m => SecretLookup m -> SecretLookup m -> SecretLookup m -> NonceTimestampCheck m -> [SignatureMethod] -> OAuthConfig m
twoLeggedConfig cons acc req = OAuthConfig cons acc req $ const (return ("", ""))

data OAuthState = OAuthState
    { oauthRawParams :: SimpleQueryText
    , reqParams      :: SimpleQueryText
    , reqUrl         :: ByteString
    , reqMethod      :: ByteString
    , oauthParams    :: OAuthParams
    }

type SecretLookup m = ByteString -> m (Either OAuthError ByteString)
type NonceTimestampCheck m = OAuthParams -> m (Maybe OAuthError)

