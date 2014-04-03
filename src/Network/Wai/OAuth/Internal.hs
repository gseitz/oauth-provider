module Network.Wai.OAuth.Internal where

import           Data.ByteString

import           Network.Wai.OAuth.Types

bsSecretLookup :: Monad m => (ByteString -> t) -> SecretLookup t m -> SecretLookup ByteString m
bsSecretLookup f l = l . f

data OAuthState = OAuthState
    { oauthRawParams :: SimpleQueryText
    , reqParams      :: SimpleQueryText
    , reqUrl         :: ByteString
    , reqMethod      :: ByteString
    , oauthParams    :: OAuthParams
    }
