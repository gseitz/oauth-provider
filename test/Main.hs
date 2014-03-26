module Main where

import qualified UnitTests as U
import Test.Tasty

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "wai-oauth test-suite" [U.tests]
