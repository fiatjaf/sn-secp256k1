sn-secp256k1
============

Scala 3 Native bindings to [libsecp256k1](https://github.com/bitcoin-core/secp256k1/).

Installation
------------

```sbt
libraryDependencies += "com.fiatjaf" %%% "sn-secp256k1" % "0.1.0"
```

Usage
-----

Here's an example that's is way too nested but shows most of the functionality:

```scala
import secp256k1.Keys

// generate a random private key
Keys.createPrivateKey() match {
  case Left(err) => println(err)
  case Right(sk) => {
    println(s"generated a secret key: ${sk.toHex}")

    // derive a public key from this private key
    sk.publicKey() match {
      case Left(err) => println(err)
      case Right(pk) => {
        println(s"derived a public key: ${pk.toHex}")

        // suppose we had received this key as hex instead
        val pkhex = pk.toHex

        // sign a message with our private key from above
        // (the thing we sign must be a 32 bytes hash of the actual message)
        val sighash = "de778d128e8ff9a3788b054a5519f0b4ba157381acace96e56337c6e520d2995"
        sk.sign(sighash) match {
          case Left(err) => println(err)
          case Right(signature) => {
            println("signed!")

            // now load the public key from a hex string (or Array[UByte])
            Keys.loadPublicKey(pkhex) match {
              case Left(err) => println(err)
              case Right(thesamepublickey) => {
                // and use it to verify the signature
                thesamepublickey.verify(sighash, signature) match {
                  case Left(err) => println(err)
                  case Right(false) => println("the signature is invalid!")
                  case Right(true) => println("the signature is valid")
                }
              }
            }
          }
        }
      }
    }
  }
}
```

Read the [Scaladoc](https://www.javadoc.io/doc/com.fiatjaf/sn-secp256k1_native0.4_3/latest/secp256k1.html) to learn more.
