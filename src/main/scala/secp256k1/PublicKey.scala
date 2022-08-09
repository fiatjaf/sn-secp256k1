package secp256k1

import scala.scalanative.unsafe._
import scala.scalanative.unsigned._

import secp256k1.UtilsExtern._
import secp256k1.Secp256k1Aux._
import secp256k1.Secp256k1Extern._
import secp256k1.Secp256k1._

case class PublicKey(value: Array[UByte]) {
  def toHex: String = bytearray2hex(value)

  def verify(
      message: Array[UByte],
      signature: Array[UByte]
  ): Either[String, Boolean] = {
    if (message.size != SIGHASH_SIZE.toInt)
      return Left(s"message must be $SIGHASH_SIZE bytes, not ${message.size}")
    if (signature.size != SIGNATURE_COMPACT_SERIALIZED_SIZE.toInt)
      return Left(
        s"message must be $SIGNATURE_COMPACT_SERIALIZED_SIZE, not ${signature.size}"
      )

    Zone { implicit z =>
      // load things in C format
      val spubkey =
        alloc[UByte](SERIALIZED_PUBKEY_SIZE).asInstanceOf[SerializedPubKey]
      for (i <- 0 until value.size) !(spubkey + i) = value(i)

      val cmessage =
        alloc[UByte](SIGHASH_SIZE).asInstanceOf[SigHash]
      for (i <- 0 until message.size) !(cmessage + i) = message(i)

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
        return Left(s"failed to parse pubkey '${bytearray2hex(value)}'")

      // parse signature
      val sig = alloc[UByte](SIGNATURE_SIZE).asInstanceOf[Signature]
      val ok2 = secp256k1_ecdsa_signature_parse_compact(ctx, sig, ssig)
      if (ok2 == 0)
        return Left(s"failed to parse signature ${bytearray2hex(signature)}")

      // check validity
      val valid = secp256k1_ecdsa_verify(ctx, sig, cmessage, pubkey)
      return Right(valid == 1)
    }
  }
  def verify(
      messagehex: String,
      signaturehex: String
  ): Either[String, Boolean] =
    verify(hex2bytearray(messagehex), hex2bytearray(signaturehex))
  def verify(
      messagehex: String,
      signature: Array[UByte]
  ): Either[String, Boolean] =
    verify(hex2bytearray(messagehex), signature)
  def verify(
      message: Array[UByte],
      signaturehex: String
  ): Either[String, Boolean] =
    verify(message, hex2bytearray(signaturehex))

  def multiply(tweak: Array[UByte]): PublicKey = Zone { implicit z =>
    // load things in C format
    val spubkey =
      alloc[UByte](SERIALIZED_PUBKEY_SIZE).asInstanceOf[SerializedPubKey]
    for (i <- 0 until value.size) !(spubkey + i) = value(i)

    val ctweak =
      alloc[UByte](TWEAK_SIZE).asInstanceOf[Tweak32]
    for (i <- 0 until tweak.size) !(ctweak + i) = tweak(i)

    // parse pubkey
    val pubkey =
      alloc[UByte](PUBKEY_SIZE).asInstanceOf[PubKey]
    val ok1 = secp256k1_ec_pubkey_parse(
      ctx,
      pubkey,
      spubkey,
      SERIALIZED_PUBKEY_SIZE
    )

    // actually perform multiplication (in-place)
    secp256k1_ec_pubkey_tweak_mul(ctx, pubkey, ctweak)

    // serialize tweaked public key
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
  def multiply(tweak: String): PublicKey = multiply(hex2bytearray(tweak))

  def add(tweak: Array[UByte]): PublicKey = Zone { implicit z =>
    // load things in C format
    val spubkey =
      alloc[UByte](SERIALIZED_PUBKEY_SIZE).asInstanceOf[SerializedPubKey]
    for (i <- 0 until value.size) !(spubkey + i) = value(i)

    val ctweak =
      alloc[UByte](TWEAK_SIZE).asInstanceOf[Tweak32]
    for (i <- 0 until tweak.size) !(ctweak + i) = tweak(i)

    // parse pubkey
    val pubkey =
      alloc[UByte](PUBKEY_SIZE).asInstanceOf[PubKey]
    secp256k1_ec_pubkey_parse(
      ctx,
      pubkey,
      spubkey,
      SERIALIZED_PUBKEY_SIZE
    )

    // actually perform addition (in-place)
    secp256k1_ec_pubkey_tweak_add(ctx, pubkey, ctweak)

    // serialize tweaked public key
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
  def add(tweak: String): PublicKey = add(hex2bytearray(tweak))

  def negate(): PublicKey = Zone { implicit z =>
    // load things in C format
    val spubkey =
      alloc[UByte](SERIALIZED_PUBKEY_SIZE).asInstanceOf[SerializedPubKey]
    for (i <- 0 until value.size) !(spubkey + i) = value(i)

    // parse pubkey
    val pubkey =
      alloc[UByte](PUBKEY_SIZE).asInstanceOf[PubKey]
    secp256k1_ec_pubkey_parse(
      ctx,
      pubkey,
      spubkey,
      SERIALIZED_PUBKEY_SIZE
    )

    // actually perform negateition (in-place)
    secp256k1_ec_pubkey_negate(ctx, pubkey)

    // serialize negated public key
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
