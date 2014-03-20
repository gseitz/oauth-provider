{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
module Network.Wai.OAuth.Types where

import           Control.Applicative        (Applicative)
import           Control.Concurrent.MonadIO (MonadIO)
import           Control.Monad.State        (MonadState, get, put)
import           Control.Monad.Trans        (MonadTrans, lift)
import           Control.Monad.Trans.Either (EitherT)
import           Control.Monad.Trans.State  (StateT)
import           Data.ByteString            (ByteString)
import           Data.Text                  (Text)
import           Network.Wai                (Request)

data SignatureMethod = HMAC_SHA1 | RSA_SHA1 | Plaintext deriving (Show, Enum)

data OAuthRequestType = OneLegged
                      | TwoLeggedRequest | TwoLeggedToken
                      | ThreeLeggedRequest | ThreeLeggedAuthorize | ThreeLeggedToken
                      deriving Show

data OAuthParams = OAuthParams {
    opConsumerKey     :: ByteString,
    opToken           :: Maybe ByteString,
    opSignatureMethod :: SignatureMethod,
    opCallback        :: Maybe ByteString,
    opSignature       :: ByteString,
    opNonce           :: ByteString,
    opTimestamp       :: ByteString
    } deriving Show

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
                | MissingHostHeader
                deriving Show

data OAuthKey = ConsumerKey ByteString | Token (Maybe ByteString) deriving Show

type SimpleQueryText = [(Text, Text)]
type RequestMethod = ByteString
type NormalizedURL = ByteString
type ParamString = ByteString
type ConsumerSecret = ByteString
type TokenSecret = ByteString
type Secrets = (ConsumerSecret, TokenSecret)



newtype OAuthT s m a = OAuthT { runOAuthT :: StateT s m a } deriving (Functor, Applicative, Monad, MonadIO)
type OAuthM m a = OAuthT Request (EitherT OAuthError m) a

instance Monad m => MonadState s (OAuthT s m) where
    get = OAuthT get
    put s = OAuthT $ put s

instance MonadTrans (OAuthT s) where
    lift = OAuthT . lift


data OAuthState = OAuthState
    { oauthRawParams :: SimpleQueryText
    , reqParams      :: SimpleQueryText
    , reqUrl         :: ByteString
    , reqMethod      :: ByteString
    , oauthParams    :: OAuthParams
    }

type SecretLookup m = OAuthKey -> m (Either OAuthError ByteString)
