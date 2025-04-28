{-# LANGUAGE OverloadedStrings, DuplicateRecordFields, RecordWildCards #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Geta.Login.CreateUser
( createUser
, createUser'
, createUserWithConnection
, createUserWithConnection'
, CreateUserDBList (..)
, defaultCreateUser
, CreateUserError
) where

-- Base imports
import Data.Functor.Contravariant (contramap)
import Data.Foldable (fold, sequenceA_)
import Data.Bifunctor (first)
import Control.Monad (join)

-- Reimports from the library.
import Geta.Login.Reexports (EmailAddress)
import Geta.Login.Reexports qualified as Reexports
import Geta.Login.Utils.Internal
  ( toHexText,
    argon2HashPasswordIO,
    getRandomBytesNoClass
  )

-- Quasi-standard Haskell type imports.
import Data.Text (Text)
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Data.ByteString (ByteString)

-- Hasql imports
import Hasql.Session qualified as Session
import Hasql.Pipeline qualified as Pipeline
import Hasql.Statement qualified as Statement
import Hasql.Encoders qualified as Encoders
import Hasql.Decoders qualified as Decoders
import Hasql.Connection (Connection)

newtype CreateUserError = MkCreateUserError
    (Either
        Reexports.CryptoError
        Session.SessionError
    )
    deriving Show

fromCryptoError :: Reexports.CryptoError -> CreateUserError
fromCryptoError = MkCreateUserError . Left

fromSessionError :: Session.SessionError -> CreateUserError
fromSessionError = MkCreateUserError . Right

data CreateUserDBList = MkCreateUserDBList
    { usersDB :: Text
    , emailsDB :: Text
    , creationTimesDB :: Text
    , validationKeysDB :: Text
    , userStatusDB :: Text
    } deriving Show

defaultCreateUser :: CreateUserDBList
defaultCreateUser = MkCreateUserDBList
    { usersDB = "users"
    , emailsDB = "user_emails"
    , creationTimesDB = "user_creation_times"
    , validationKeysDB = "user_activation_keys"
    , userStatusDB = "user_status"
    }

createUser :: a
createUser = undefined

createUser' :: a
createUser' = undefined

{-| Variant of createUser that allows providing your own connection. -}
createUserWithConnection
    :: Connection -- ^ Hasql connection.
    -> Text -- ^ Username
    -> Text -- ^ Password
    -> EmailAddress -- ^ E-mail address formatted via email-validate's
                    -- functions, see Geta.Login.Reexports
    -> IO (Either CreateUserError Text)
createUserWithConnection = createUserWithConnection' defaultCreateUser

{-| Variant of createUserWithConnection that allows specification of
databases in use. Actually the worker function of that function. -}
createUserWithConnection'
    :: CreateUserDBList -- ^ Record type holding DB fields.
    -> Connection -- ^ Hasql connection.
    -> Text -- ^ Username
    -> Text -- ^ Password
    -> EmailAddress -- ^ E-mail address formatted via email-validate's
                    -- functions, see Geta.Login.Reexports
    -> IO (Either CreateUserError Text)
createUserWithConnection' MkCreateUserDBList {..} conn username pass email = do

    -- Outline of function, traverse only acts if no error occurs,
    -- fmap join removes nesting of Either types.

    hashedPassAndSalt <- first fromCryptoError
        <$> argon2HashPasswordIO (encodeUtf8 pass) 512
    uuid <- fmap join $ traverse createUserPassEntry hashedPassAndSalt
    fmap join $ traverse createUuidEntries uuid

  where
    createUserPassEntry (hashedPassword, passwordSalt) =
        fmap (first fromSessionError)
        $ flip Session.run conn $ Session.statement
            ( encodeUtf8 usersDB, username, hashedPassword, passwordSalt)
            $ Statement.Statement
                ("INSERT INTO $1 VALUES \
                \(DEFAULT, $2 , $3 , $4 ) \
                \RETURNING uid;")
                ( fold [ Encoders.char  ⭐ \(a,_,_,_) -> a
                       , Encoders.text  ⭐ \(_,b,_,_) -> b
                       , Encoders.bytea ⭐ \(_,_,c,_) -> c
                       , Encoders.bytea ⭐ \(_,_,_,d) -> d
                       ]
                )
                ( Decoders.singleRow
                    $ Decoders.column
                    $ Decoders.nonNullable
                    $ Decoders.uuid
                )
                False

    encoder ⭐ selector = contramap selector $ Encoders.param
        $ Encoders.nonNullable encoder
    infix 8 ⭐

    makeValidationKey :: IO ByteString
    makeValidationKey = getRandomBytesNoClass 512

    createUuidEntries uuid = fmap (first fromSessionError) $ do
        makeValidationKey >>= \key -> fmap (toHexText key <$) $ flip Session.run conn
            $ Session.pipeline
                $ sequenceA_
                    [ Pipeline.statement (creationTimesDB, uuid)
                        $ dynStatementNoRes
                            "INSERT INTO $1 VALUES \
                            \( $2 , DEFAULT );"
                            $  Encoders.name ⭐ fst
                            <> Encoders.uuid ⭐ snd
                    , Pipeline.statement (userStatusDB, uuid)
                        $ dynStatementNoRes
                            "INSERT INTO $1 VALUES \
                            \( $2 , DEFAULT );"
                            $  Encoders.name ⭐ fst
                            <> Encoders.uuid ⭐ snd
                    , Pipeline.statement
                        ( emailsDB
                        , uuid
                        , decodeUtf8 $ Reexports.toByteString email
                        )
                        $ dynStatementNoRes
                            "INSERT INTO $1 VALUES \
                            \( $2 , $3 );"
                        $  fold [ Encoders.name ⭐ \(a,_,_) -> a
                                , Encoders.uuid ⭐ \(_,b,_) -> b
                                , Encoders.text ⭐ \(_,_,c) -> c
                                ]
                    , Pipeline.statement
                        (validationKeysDB, uuid, key)
                        $ dynStatementNoRes
                            "INSERT INTO $1 VALUES \
                            \( $2 , $3 );"
                        $  fold [ Encoders.name  ⭐ \(a,_,_) -> a
                                , Encoders.uuid  ⭐ \(_,b,_) -> b
                                , Encoders.bytea ⭐ \(_,_,c) -> c
                                ]
                    ]

    -- | Statement for pipeline with constant arguments preapplied.
    dynStatementNoRes sql encoder =
        Statement.Statement sql encoder Decoders.noResult False
