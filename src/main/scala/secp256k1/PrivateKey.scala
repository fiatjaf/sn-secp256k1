package secp256k1

import scala.scalanative.unsafe._
import scala.scalanative.unsigned._

import secp256k1.UtilsExtern._
import secp256k1.Secp256k1Aux._
import secp256k1.Secp256k1Extern._
import secp256k1.Secp256k1._

case class PrivateKey(privateKey: Array[UByte]) {
  def toHex: String = bytearray2hex(privateKey)

  def publicKey(): PublicKey = {
    Zone { implicit z =>
      {
        // load private key into C form
        val seckey = alloc[UByte](SECKEY_SIZE).asInstanceOf[SecKey]
        for (i <- 0 until privateKey.size) !(seckey + i) = privateKey(i)

        // create public key
        val pubkey = alloc[UByte](PUBKEY_SIZE).asInstanceOf[PubKey]
        secp256k1_ec_pubkey_create(ctx, pubkey, seckey)

        // serialize public key
        val spubkey =
          alloc[UByte](SERIALIZED_PUBKEY_SIZE).asInstanceOf[SerializedPubKey]

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
        PublicKey(spkey)
      }
    }
  }

  def sign(sighash: Array[UByte]): Either[String, Array[UByte]] = {
    Zone { implicit z =>
      {
        if (sighash.size != 32)
          return Left(
            s"sighash must be ${SIGHASH_SIZE.toInt} bytes, not ${sighash.size}"
          )

        // load private key into C form
        val seckey = alloc[UByte](SECKEY_SIZE).asInstanceOf[SecKey]
        for (i <- 0 until privateKey.size) !(seckey + i) = privateKey(i)

        // get sighash in C format
        val sighashc = alloc[UByte](SIGHASH_SIZE).asInstanceOf[SigHash]
        for (i <- 0 until sighash.size) !(sighashc + i) = sighash(i)

        // make signature
        val sig = alloc[UByte](SIGNATURE_SIZE).asInstanceOf[Signature]
        val ok1 =
          secp256k1_ecdsa_sign(ctx, sig, sighashc, seckey, null, null)
        if (ok1 == 0) return Left("failed to sign")

        // serialize signature
        val compactsig = alloc[UByte](SIGNATURE_COMPACT_SERIALIZED_SIZE)
          .asInstanceOf[SignatureCompactSerialized]
        val ok2 =
          secp256k1_ecdsa_signature_serialize_compact(ctx, compactsig, sig)
        if (ok2 == 0) return Left("failed to serialize signature")

        Right(
          ptr2bytearray(compactsig, SIGNATURE_COMPACT_SERIALIZED_SIZE.toInt)
        )
      }
    }
  }

  def sign(sighashhex: String): Either[String, Array[UByte]] =
    sign(hex2bytearray(sighashhex))
}
