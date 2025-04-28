{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Geta.Login.CreateUser
import Hasql.Connection
import Hasql.Connection.Setting.Connection.Param
import Hasql.Connection.Setting.Connection
import Hasql.Connection.Setting
import Geta.Login.Reexports

main = do
    foo <- acquire
      $ pure
      $ connection
      $ params [ host "localhost"
               , port 5432
               , dbname "test_db"
               , user "test_user"
               , password "GregariousOriole~"
               ]

    case foo of
        Right conn -> do
            foo <- createUserWithConnection conn "Teddy" "pass" $ case emailAddress "foo@bar.com" of
              Just a -> a
              _ -> undefined
            print foo
        Left err -> do
            print err
            undefined
