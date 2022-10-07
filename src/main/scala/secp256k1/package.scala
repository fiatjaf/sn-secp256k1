import scala.scalanative.unsafe._
import scala.scalanative.unsigned._

import secp256k1.Secp256k1._

package object secp256k1 {
  import secp256k1.UtilsExtern._
  import secp256k1.Secp256k1Aux._
  import secp256k1.Secp256k1Extern._

  def createPrivateKey(): PrivateKey = Zone { implicit z =>
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

  def loadPrivateKey(bytes: Array[UByte]): Either[String, PrivateKey] =
    Zone { implicit z =>
      // check size
      if (bytes.size != SECKEY_SIZE.toInt)
        Left(
          s"invalid private key size, must be $SECKEY_SIZE bytes, not ${bytes.size}"
        )
      else {
        // load private key into C form
        val seckey = alloc[UByte](SECKEY_SIZE).asInstanceOf[SecKey]
        for (i <- 0 until bytes.size) !(seckey + i) = bytes(i)

        // check validity
        val validity = secp256k1_ec_seckey_verify(ctx, seckey)
        if (validity == 0) Left("private key outside allowed range")
        else
          // return the key object
          Right(PrivateKey(bytes))
      }
    }

  def loadPrivateKey(hex: String): Either[String, PrivateKey] =
    loadPrivateKey(hex2bytearray(hex))

  def loadPublicKey(bytes: Array[UByte]): Either[String, PublicKey] =
    Zone { implicit z =>
      // check size
      if (
        bytes.size != SERIALIZED_PUBKEY_SIZE.toInt &&
        bytes.size != SERIALIZED_UNCOMPRESSED_PUBKEY_SIZE.toInt
      )
        Left(
          s"invalid pubkey size, must be ${SERIALIZED_PUBKEY_SIZE.toInt} or ${SERIALIZED_UNCOMPRESSED_PUBKEY_SIZE.toInt} bytes, not ${bytes.size}"
        )
      else {
        // load into C form
        val spubkey =
          alloc[UByte](bytes.size.toULong).asInstanceOf[SecKey]
        for (i <- 0 until bytes.size) !(spubkey + i) = bytes(i)

        // parse serialized pubkey
        val pubkey = alloc[UByte](PUBKEY_SIZE).asInstanceOf[PubKey]
        val ok =
          secp256k1_ec_pubkey_parse(
            ctx,
            pubkey,
            spubkey,
            bytes.size.toULong
          )
        if (ok == 0) Left("failed to parse serialized pubkey")
        else {
          // serialize public key as compressed
          val scpubkey =
            alloc[UByte](SERIALIZED_PUBKEY_SIZE).asInstanceOf[Ptr[UByte]]

          val sizeptr = alloc[CSize](1)
          !sizeptr = SERIALIZED_PUBKEY_SIZE

          secp256k1_ec_pubkey_serialize(
            ctx,
            scpubkey,
            sizeptr,
            pubkey,
            EC_COMPRESSED
          )

          // return the key object
          Right(
            PublicKey(ptr2bytearray(scpubkey, SERIALIZED_PUBKEY_SIZE.toInt))
          )
        }
      }
    }

  def loadPublicKey(hex: String): Either[String, PublicKey] =
    loadPublicKey(hex2bytearray(hex))

  def recoverPublicKey(
      message: Array[UByte],
      signature: Array[UByte],
      recoveryId: Int
  ): Either[String, PublicKey] = {
    // check sizes
    if (message.size != SIGHASH_SIZE.toInt)
      Left(
        s"invalid message hash size, must be ${SIGHASH_SIZE.toInt} bytes, not ${message.size}"
      )
    else if (signature.size != SIGNATURE_COMPACT_SERIALIZED_SIZE.toInt)
      Left(
        s"invalid signature size, must be ${SIGNATURE_COMPACT_SERIALIZED_SIZE.toInt} bytes, not ${signature.size}"
      )
    else
      Zone { implicit z =>
        // load into C form
        val cmessage =
          alloc[UByte](SIGHASH_SIZE).asInstanceOf[SigHash]
        for (i <- 0 until message.size) !(cmessage + i) = message(i)

        val ssig =
          alloc[UByte](SIGNATURE_COMPACT_SERIALIZED_SIZE).asInstanceOf[SecKey]
        for (i <- 0 until signature.size) !(ssig + i) = signature(i)

        // actually perform the recovery
        val recoverablesignature = alloc[UByte](SIGNATURE_RECOVERABLE_SIZE)
        if (
          secp256k1_ecdsa_recoverable_signature_parse_compact(
            ctx,
            recoverablesignature,
            ssig,
            recoveryId
          ) == 0
        ) Left("failed to parse recoverable signature")
        else {
          val pubkey = alloc[UByte](PUBKEY_SIZE)
          if (
            secp256k1_ecdsa_recover(
              ctx,
              pubkey,
              recoverablesignature,
              cmessage
            ) == 0
          ) Left("failed to recover public key from signature")
          else {
            // serialize into public key
            val spubkey =
              alloc[UByte](SERIALIZED_PUBKEY_SIZE).asInstanceOf[Ptr[UByte]]

            val sizeptr = alloc[CSize](1)
            !sizeptr = SERIALIZED_PUBKEY_SIZE

            secp256k1_ec_pubkey_serialize(
              ctx,
              spubkey,
              sizeptr,
              pubkey,
              EC_COMPRESSED
            )

            val spkey = ptr2bytearray(spubkey, SERIALIZED_PUBKEY_SIZE.toInt)
            Right(PublicKey(spkey))
          }
        }
      }
  }
}
