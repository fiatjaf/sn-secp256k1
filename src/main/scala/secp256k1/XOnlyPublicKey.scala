package secp256k1

import scala.scalanative.unsafe._
import scala.scalanative.unsigned._

import secp256k1.UtilsExtern._
import secp256k1.Secp256k1Aux._
import secp256k1.Secp256k1Extern._
import secp256k1.Secp256k1._

case class XOnlyPublicKey(value: Array[UByte]) {
  require(
    value.size == 32,
    "XOnlyPublicKey value must be only 32 bytes (the X coordinates of the point)."
  )

  def toHex: String = bytearray2hex(value)

  def verifySchnorr(
      message: Array[UByte],
      signature: Array[UByte]
  ): Either[String, Boolean] = {
    if (message.size != SIGHASH_SIZE.toInt)
      Left(s"message must be $SIGHASH_SIZE bytes, not ${message.size}")
    else if (signature.size != 64)
      Left(s"message must be 64, not ${signature.size}")
    else
      Zone { implicit z =>
        // load things in C format
        val spubkey =
          alloc[UByte](32L.toULong).asInstanceOf[Ptr[UByte]]
        for (i <- 0 until 32) !(spubkey + i) = value(i)

        val cmessage =
          alloc[UByte](SIGHASH_SIZE).asInstanceOf[SigHash]
        for (i <- 0 until message.size) !(cmessage + i) = message(i)

        val ssig =
          alloc[UByte](96L.toULong).asInstanceOf[Ptr[UByte]]
        for (i <- 0 until 96) !(ssig + i) = signature(i)

        // parse pubkey into xonly pubkey object
        val xonlypubkey =
          alloc[UByte](XONLYPUBKEY_SIZE).asInstanceOf[XOnlyPubKey]
        val ok1 = secp256k1_xonly_pubkey_parse(
          ctx,
          xonlypubkey,
          spubkey
        )
        if (ok1 == 0) Left(s"failed to parse pubkey '${bytearray2hex(value)}'")
        else {
          // check validity
          val valid = secp256k1_schnorrsig_verify(
            ctx,
            ssig,
            cmessage,
            32L.toULong,
            xonlypubkey
          )
          Right(valid == 1)
        }
      }
  }

  def verifySchnorr(
      messagehex: String,
      signaturehex: String
  ): Either[String, Boolean] =
    verifySchnorr(hex2bytearray(messagehex), hex2bytearray(signaturehex))
  def verifySchnorr(
      messagehex: String,
      signature: Array[UByte]
  ): Either[String, Boolean] =
    verifySchnorr(hex2bytearray(messagehex), signature)
  def verifySchnorr(
      message: Array[UByte],
      signaturehex: String
  ): Either[String, Boolean] =
    verifySchnorr(message, hex2bytearray(signaturehex))
}
