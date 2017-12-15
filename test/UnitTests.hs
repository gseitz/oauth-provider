{-# LANGUAGE OverloadedStrings #-}
module UnitTests where

import           Test.Tasty
import           Test.Tasty.HUnit

import qualified Data.ByteString            as B

import           Network.OAuth.Provider.OAuth1
import           Network.OAuth.Provider.OAuth1.Internal
import           Network.OAuth.Provider.OAuth1.Types

tests :: TestTree
tests = testGroup "HUnit tests" [
    signatureTests, extractOAuthParametersTests, parseAuthHeaderTests
    ]

signatureTests :: TestTree
signatureTests = testGroup "Signature tests" [
        hmacSha1SignatureTest, plainTextSignatureTest, rsaSha1SignatureTest
    ]
  where
    hmacSha1SignatureTest = testCase "HMAC-SHA1 signature" $
        mkSignature HMAC_SHA1 ("kd94hf93k423kf44", "pfkkdhi9sl3r4s00") baseString @?= Signature "QnAoyJcVeC9988ZnawQI+K6XrRA="
    plainTextSignatureTest = testCase "PLAINTEXT signature" $
        mkSignature Plaintext ("foo", "bar") undefined @?= Signature "foo&bar"
    rsaSha1SignatureTest = testCase "RSA-SHA1 signature is unsupported" $
        extractSignatureMethod "RSA-SHA1" @?= Left (UnsupportedSignatureMethod "RSA-SHA1")

extractOAuthParametersTests :: TestTree
extractOAuthParametersTests = testGroup "OAuth param extraction tests"
    [ testCase "multiple oauth parameter locations" $ validateAndExtractParams params1 params2 [] @?= Left MultipleOAuthParamLocations
    , testCase "detect duplicate parameters" $ validateAndExtractParams params3 [] [] @?= Left (DuplicateParameter "oauth_nonce")
    , testCase "detect unsupported parameters" $ validateAndExtractParams params4 [] [] @?= Left (UnsupportedParameter "oauth_foo")
    ]
  where
    params1 = [("oauth_nonce", "abc123")]
    params2 = [("oauth_timestamp", "1234567")]
    params3 = [("oauth_nonce", "xyz789"), ("oauth_nonce", "abc123")]
    params4 = [("oauth_foo", "bar")]

baseString :: B.ByteString
baseString = "GET&http%3A%2F%2Flocalhost%3A3000%2F&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal"

parseAuthHeaderTests :: TestTree
parseAuthHeaderTests = testGroup "Parse OAuth header tests"
    [ testCase "percent-encoded values" $ parseAuthHeader authorizationHeader @?=
        [ ("oauth_signature","some-consumer-secret&")
        , ("oauth_signature_method","PLAINTEXT")
        , ("oauth_consumer_key","some-oauth-consumer-key")
        , ("oauth_version","1.0")
        , ("oauth_timestamp","1502557142")
        , ("oauth_nonce","000")
        , ("oauth_callback","https://localhost:3443/auth/page/callbackpage")
        ]
    ]
  where
    authorizationHeader :: B.ByteString
    authorizationHeader = "OAuth oauth_signature=\"some-consumer-secret%26\",oauth_signature_method=\"PLAINTEXT\",oauth_consumer_key=\"some-oauth-consumer-key\",oauth_version=\"1.0\",oauth_timestamp=\"1502557142\",oauth_nonce=\"000\",oauth_callback=\"https%3A%2F%2Flocalhost%3A3443%2Fauth%2Fpage%2Fcallbackpage\""


