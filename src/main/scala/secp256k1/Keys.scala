package secp256k1

import scala.scalanative.unsafe._
import scala.scalanative.unsigned._

import secp256k1.UtilsExtern._
import secp256k1.Secp256k1Aux._
import secp256k1.Secp256k1Extern._
import secp256k1.Secp256k1._

object Keys {
  def createPrivateKey(): PrivateKey = {
    Zone { implicit z =>
      {
        // create private key
        val seckey = alloc[UByte](SECKEY_SIZE).asInstanceOf[SecKey]
        val ok = fill_random(seckey, SECKEY_SIZE)
        if (ok == 0) {
          throw Exception("failed to gather randomness for secret key")
        }
        var validity = 0
        while (validity == 0)
          validity = secp256k1_ec_seckey_verify(ctx, seckey)

        // serialize private key
        val sskey = ptr2bytearray(seckey, SECKEY_SIZE.toInt)

        // return the key object
        PrivateKey(sskey)
      }
    }
  }

  def loadPrivateKey(bytes: Array[UByte]): Either[String, PrivateKey] = {
    Zone { implicit z =>
      {
        // check size
        if (bytes.size != SECKEY_SIZE.toInt)
          return Left(
            s"invalid private key size, must be $SECKEY_SIZE bytes, not ${bytes.size}"
          )

        // load private key into C form
        val seckey = alloc[UByte](SECKEY_SIZE).asInstanceOf[SecKey]
        for (i <- 0 until bytes.size) !(seckey + i) = bytes(i)

        // check validity
        val validity = secp256k1_ec_seckey_verify(ctx, seckey)
        if (validity == 0) return Left("private key outside allowed range")

        // return the key object
        Right(PrivateKey(bytes))
      }
    }
  }

  def loadPrivateKey(hex: String): Either[String, PrivateKey] =
    loadPrivateKey(hex2bytearray(hex))

  def loadPublicKey(bytes: Array[UByte]): Either[String, PublicKey] = {
    Zone { implicit z =>
      {
        // check size
        if (bytes.size != SERIALIZED_PUBKEY_SIZE.toInt)
          return Left(
            s"invalid hex string size, must be ${SERIALIZED_PUBKEY_SIZE.toInt} bytes, not ${bytes.size}"
          )

        // load into C form
        val spubkey =
          alloc[UByte](SERIALIZED_PUBKEY_SIZE).asInstanceOf[SecKey]
        for (i <- 0 until bytes.size) !(spubkey + i) = bytes(i)

        // parse serialized pubkey
        val pubkey = alloc[UByte](PUBKEY_SIZE).asInstanceOf[PubKey]
        val ok =
          secp256k1_ec_pubkey_parse(
            ctx,
            pubkey,
            spubkey,
            SERIALIZED_PUBKEY_SIZE
          )
        if (ok == 0) return Left("failed to parse serialized pubkey")

        // return the key object
        Right(PublicKey(bytes))
      }
    }
  }

  def loadPublicKey(hex: String): Either[String, PublicKey] =
    loadPublicKey(hex2bytearray(hex))
}
