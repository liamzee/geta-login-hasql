module Geta.Login.Utils.Internal
( toHexText
, argon2HashPasswordIO
, getRandomBytesNoClass
) where

import Data.Bifunctor

import Data.ByteString (ByteString)
import Data.ByteString qualified as ByteString
import Data.Text (Text)
import Data.Text qualified as Text

import Crypto.Error qualified as Error
import Crypto.Random qualified as Random
import Crypto.KDF.Argon2 qualified as Argon2

import Data.ByteArray qualified as ByteArray

toHexText :: ByteString -> Text
toHexText = Text.pack . ByteString.foldr go []
  where
    go word8 remainder = bimap toChar toChar
        `parseChars` quotRem word8 16 <> remainder

    infix 9 `parseChars`
    parseChars mapping results = let (a,b) = mapping results in [a,b]

    -- Not going to add to compile times by importing Data.Map,
    -- nor am I going to sacrifice efficiency by doing a lookup
    -- through a list.

    toChar elem = if elem <= 7
        then if elem <= 3
            then if elem <= 1
                then if elem == 0
                    then '0'
                    else '1'
                else if elem == 2
                    then '2'
                    else '3'
            else if elem <= 5
                then if elem == 4
                    then '4'
                    else '5'
                else if elem == 6
                    then '6'
                    else '7'
        else if elem <= 11
            then if elem <= 9
                then if elem == 8
                    then '8'
                    else '9'
                else if elem == 10
                    then 'a'
                    else 'b'
            else if elem <= 13
                then if elem == 12
                    then 'c'
                    else 'd'
                else if elem == 14
                    then 'e'
                    else 'f'
{-# INLINABLE toHexText #-}

argon2HashPasswordIO
    :: ByteString
    -> Int -- ^ length of hash result
    -> IO (Either Error.CryptoError (ByteString, ByteString))
argon2HashPasswordIO password saltLength = do
    salt <- Random.seedNew
    case Argon2.hash Argon2.defaultOptions password salt saltLength of
        Error.CryptoPassed hashed ->
            pure $ Right ( hashed, ByteArray.convert salt )
        Error.CryptoFailed err -> pure $ Left err
{-# INLINABLE argon2HashPasswordIO #-}

getRandomBytesNoClass :: Int -> IO ByteString
getRandomBytesNoClass = Random.getRandomBytes
{-# INLINABLE getRandomBytesNoClass #-}
