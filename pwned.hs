-- FAIR License, Copyright (c) 2019 davidxbors
-- Usage of the works is permitted provided that this instrument is retained
-- with the works, so that any entity that uses the works is notified of this instrument
-- DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.

{-# LANGUAGE OverloadedStrings #-}

import qualified Data.ByteString.Lazy as B
import Data.ByteString.Lazy.Char8 as Char8 (unpack)
import Network.HTTP.Conduit
import Crypto.Hash
import Data.ByteString (ByteString)
import Data.ByteString.Char8 as C (pack)
import Data.List.Split
import Data.Char
import System.Environment

get :: String -> IO B.ByteString
get url = simpleHttp url

up str = [toUpper char | char <- str]

main :: IO ()
main = do
  -- get the password from the command line args and make it a ByteString
  args <- getArgs
  let password = C.pack $ args !! 0
  
  -- hashing the password
  let hashedPassword = up . show $ hashWith SHA1 password
  
  -- getting the first 5 bytes of the hash, and the rest of the hash in 2 separate variables
  let ffive = take 5 hashedPassword
  let lfive = drop 5 hashedPassword

  -- get the data from the api
  bodyy <- get $ "https://api.pwnedpasswords.com/range/" ++ ffive
  let textFromBody = Char8.unpack $ bodyy

  -- search for the hash and save it together with it's count
  let lines = splitOn "\r\n" textFromBody
  let ourHash = head [hash | hash <- lines, head (splitOn ":" hash) == lfive]

  -- finally tell the user how many times his password has been seen, and also the hash of his password
  putStrLn $ "Your password has the hash: " ++ (show $ (splitOn ":" ourHash) !! 0) ++ "and has been seen " ++ (show $ (splitOn ":" ourHash) !! 1) ++ " times before!"
