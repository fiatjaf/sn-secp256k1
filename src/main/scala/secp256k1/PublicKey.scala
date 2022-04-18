package secp256k1

import scala.scalanative.unsafe._
import scala.scalanative.unsigned._

import secp256k1.UtilsExtern._
import secp256k1.Secp256k1Aux._
import secp256k1.Secp256k1Extern._
import secp256k1.Secp256k1._

case class PublicKey(publicKey: Array[UByte]) {
  def toHex: String = bytearray2hex(publicKey)

  def verify(
      sighash: Array[UByte],
      signature: Array[UByte]
  ): Either[String, Boolean] = {
    if (sighash.size != SIGHASH_SIZE.toInt)
      return Left(s"sighash must be $SIGHASH_SIZE bytes, not ${sighash.size}")
    if (signature.size != SIGNATURE_COMPACT_SERIALIZED_SIZE.toInt)
      return Left(
        s"sighash must be $SIGNATURE_COMPACT_SERIALIZED_SIZE, not ${signature.size}"
      )

    Zone { implicit z =>
      {
        // load things in C format
        val spubkey =
          alloc[UByte](SERIALIZED_PUBKEY_SIZE).asInstanceOf[SerializedPubKey]
        for (i <- 0 until publicKey.size) !(spubkey + i) = publicKey(i)

        val csighash =
          alloc[UByte](SIGHASH_SIZE).asInstanceOf[SigHash]
        for (i <- 0 until sighash.size) !(csighash + i) = sighash(i)

        val ssig =
          alloc[UByte](SIGNATURE_COMPACT_SERIALIZED_SIZE).asInstanceOf[SecKey]
        for (i <- 0 until signature.size) !(ssig + i) = signature(i)

        // parse pubkey
        val pubkey =
          alloc[UByte](PUBKEY_SIZE).asInstanceOf[PubKey]
        val ok1 = secp256k1_ec_pubkey_parse(
          ctx,
          pubkey,
          spubkey,
          SERIALIZED_PUBKEY_SIZE
        )
        if (ok1 == 0)
          return Left(s"failed to parse pubkey '${bytearray2hex(publicKey)}'")

        // parse signature
        val sig = alloc[UByte](SIGNATURE_SIZE).asInstanceOf[Signature]
        val ok2 = secp256k1_ecdsa_signature_parse_compact(ctx, sig, ssig)
        if (ok2 == 0)
          return Left(s"failed to parse signature ${bytearray2hex(signature)}")

        // check validity
        val valid = secp256k1_ecdsa_verify(ctx, sig, csighash, pubkey)
        return Right(valid == 1)
      }
    }
  }
  def verify(
      sighashhex: String,
      signaturehex: String
  ): Either[String, Boolean] =
    verify(hex2bytearray(sighashhex), hex2bytearray(signaturehex))
  def verify(
      sighashhex: String,
      signature: Array[UByte]
  ): Either[String, Boolean] =
    verify(hex2bytearray(sighashhex), signature)
  def verify(
      sighash: Array[UByte],
      signaturehex: String
  ): Either[String, Boolean] =
    verify(sighash, hex2bytearray(signaturehex))
}
