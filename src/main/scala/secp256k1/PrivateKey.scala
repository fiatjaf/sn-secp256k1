package secp256k1

import scala.scalanative.unsafe._
import scala.scalanative.unsigned._

import secp256k1.UtilsExtern._
import secp256k1.Secp256k1Aux._
import secp256k1.Secp256k1Extern._
import secp256k1.Secp256k1._

case class PrivateKey(value: Array[UByte]) {
  def toHex: String = bytearray2hex(value)

  def publicKey(): PublicKey = Zone { implicit z =>
    // load private key into C form
    val seckey = alloc[UByte](SECKEY_SIZE).asInstanceOf[SecKey]
    for (i <- 0 until value.size) !(seckey + i) = value(i)

    // create public key
    val pubkey = alloc[UByte](PUBKEY_SIZE).asInstanceOf[PubKey]
    secp256k1_ec_pubkey_create(ctx, pubkey, seckey)

    // serialize public key as compressed
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
    PublicKey(spkey)
  }

  def sign(message: Array[UByte]): Either[String, Array[UByte]] = Zone {
    implicit z =>
      if (message.size != 32)
        Left(
          s"message must be ${SIGHASH_SIZE.toInt} bytes, not ${message.size}"
        )
      else {
        // load private key into C form
        val seckey = alloc[UByte](SECKEY_SIZE).asInstanceOf[SecKey]
        for (i <- 0 until value.size) !(seckey + i) = value(i)

        // get message in C format
        val messagec = alloc[UByte](SIGHASH_SIZE).asInstanceOf[SigHash]
        for (i <- 0 until message.size) !(messagec + i) = message(i)

        // make signature
        val sig = alloc[UByte](SIGNATURE_SIZE).asInstanceOf[Signature]
        val ok1 =
          secp256k1_ecdsa_sign(ctx, sig, messagec, seckey, null, null)
        if (ok1 == 0) Left("failed to sign")
        else {
          // serialize signature
          val compactsig = alloc[UByte](SIGNATURE_COMPACT_SERIALIZED_SIZE)
            .asInstanceOf[Ptr[UByte]]
          val ok2 =
            secp256k1_ecdsa_signature_serialize_compact(ctx, compactsig, sig)
          if (ok2 == 0) Left("failed to serialize signature")
          else
            Right(
              ptr2bytearray(compactsig, SIGNATURE_COMPACT_SERIALIZED_SIZE.toInt)
            )
        }
      }
  }
  def sign(messagehex: String): Either[String, Array[UByte]] =
    sign(hex2bytearray(messagehex))

  def signSchnorr(
      message: Array[UByte],
      auxRand: Array[UByte] = Array.empty
  ): Either[String, Array[UByte]] = Zone { implicit z =>
    if (message.size != 32)
      Left(
        s"message must be ${SIGHASH_SIZE.toInt} bytes, not ${message.size}"
      )
    else {
      // load private key into C form
      val seckey = alloc[UByte](SECKEY_SIZE).asInstanceOf[SecKey]
      for (i <- 0 until value.size) !(seckey + i) = value(i)

      // get message in C format
      val messagec = alloc[UByte](SIGHASH_SIZE).asInstanceOf[SigHash]
      for (i <- 0 until message.size) !(messagec + i) = message(i)

      // build keypair object from seckey
      val keypair = alloc[UByte](KEYPAIR_SIZE).asInstanceOf[KeyPair]
      val ok0 = secp256k1_keypair_create(ctx, keypair, seckey)
      if (ok0 == 0) Left("failed to build keypair from secret key")
      else {
        // gather 32 random bytes
        val aux_rand32_opt: Option[Ptr[UByte]] = {
          val r = alloc[UByte](32).asInstanceOf[Ptr[UByte]]
          if (auxRand.size == 32) {
            for (i <- 0 until 32) !(r + i) = auxRand(i)
            Some(r)
          } else {
            val ok0 = fill_random(r, 32L.toULong)
            if (ok0 == 0) None
            else Some(r)
          }
        }

        aux_rand32_opt match {
          case None =>
            Left("failed to gather randomness for aux_rand32")
          case Some(aux_rand32) =>
            // make signature
            val sig = alloc[UByte](SIGNATURE_SIZE).asInstanceOf[Signature]
            val ok1 =
              secp256k1_schnorrsig_sign32(
                ctx,
                sig,
                messagec,
                keypair,
                aux_rand32
              )
            if (ok1 == 0) Left("failed to sign")
            else
              // the signature is just transparent 64 bytes, no fancy objects, so we just return it
              Right(ptr2bytearray(sig, 64))
        }
      }
    }
  }

  def signSchnorr(messagehex: String): Either[String, Array[UByte]] =
    signSchnorr(hex2bytearray(messagehex))
  def signSchnorr(
      messagehex: String,
      auxRand: String
  ): Either[String, Array[UByte]] =
    signSchnorr(hex2bytearray(messagehex), hex2bytearray(auxRand))

  def multiply(tweak: Array[UByte]): PrivateKey = Zone { implicit z =>
    // load things in C format
    val seckey = alloc[UByte](SECKEY_SIZE).asInstanceOf[SecKey]
    for (i <- 0 until value.size) !(seckey + i) = value(i)

    val ctweak =
      alloc[UByte](TWEAK_SIZE).asInstanceOf[Ptr[UByte]]
    for (i <- 0 until tweak.size) !(ctweak + i) = tweak(i)

    // actually perform multiplication (in-place)
    secp256k1_ec_seckey_tweak_mul(ctx, seckey, ctweak)

    // serialize tweaked private key
    val sskey = ptr2bytearray(seckey, SECKEY_SIZE.toInt)

    // return the key object
    PrivateKey(sskey)
  }
  def multiply(tweak: String): PrivateKey = multiply(hex2bytearray(tweak))

  def add(tweak: Array[UByte]): PrivateKey = Zone { implicit z =>
    // load things in C format
    val seckey = alloc[UByte](SECKEY_SIZE).asInstanceOf[SecKey]
    for (i <- 0 until value.size) !(seckey + i) = value(i)

    val ctweak =
      alloc[UByte](TWEAK_SIZE).asInstanceOf[Ptr[UByte]]
    for (i <- 0 until tweak.size) !(ctweak + i) = tweak(i)

    // actually perform addition (in-place)
    secp256k1_ec_seckey_tweak_add(ctx, seckey, ctweak)

    // serialize tweaked private key
    val sskey = ptr2bytearray(seckey, SECKEY_SIZE.toInt)

    // return the key object
    PrivateKey(sskey)
  }
  def add(tweak: String): PrivateKey = add(hex2bytearray(tweak))

  def negate(): PrivateKey = Zone { implicit z =>
    // load things in C format
    val seckey = alloc[UByte](SECKEY_SIZE).asInstanceOf[SecKey]
    for (i <- 0 until value.size) !(seckey + i) = value(i)

    // actually perform negateition (in-place)
    secp256k1_ec_seckey_negate(ctx, seckey)

    // serialize negated private key
    val sskey = ptr2bytearray(seckey, SECKEY_SIZE.toInt)

    // return the key object
    PrivateKey(sskey)
  }
}
