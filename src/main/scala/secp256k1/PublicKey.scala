package secp256k1

import scala.scalanative.unsafe._
import scala.scalanative.unsigned._

import secp256k1.UtilsExtern._
import secp256k1.Secp256k1Aux._
import secp256k1.Secp256k1Extern._
import secp256k1.Secp256k1._

case class PublicKey(value: Array[UByte]) {
  require(
    value.size == 33,
    "PublicKey value must be in serialized 33-byte format. Use secp256k1.loadPublicKey() instead."
  )

  def toHex: String = bytearray2hex(value)
  def xonly: XOnlyPublicKey = XOnlyPublicKey(value.drop(1))

  def verify(
      message: Array[UByte],
      signature: Array[UByte]
  ): Either[String, Boolean] =
    if (message.size != SIGHASH_SIZE.toInt)
      Left(s"message must be $SIGHASH_SIZE bytes, not ${message.size}")
    else if (signature.size != SIGNATURE_COMPACT_SERIALIZED_SIZE.toInt)
      Left(
        s"message must be $SIGNATURE_COMPACT_SERIALIZED_SIZE, not ${signature.size}"
      )
    else
      Zone { implicit z =>
        // load things in C format
        val spubkey =
          alloc[UByte](SERIALIZED_PUBKEY_SIZE).asInstanceOf[Ptr[UByte]]
        for (i <- 0 until value.size) !(spubkey + i) = value(i)

        val cmessage =
          alloc[UByte](SIGHASH_SIZE).asInstanceOf[SigHash]
        for (i <- 0 until message.size) !(cmessage + i) = message(i)

        val ssig =
          alloc[UByte](SIGNATURE_COMPACT_SERIALIZED_SIZE)
            .asInstanceOf[Ptr[UByte]]
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
        if (ok1 == 0) Left(s"failed to parse pubkey '${bytearray2hex(value)}'")
        else {
          // parse signature
          val sig = alloc[UByte](SIGNATURE_SIZE).asInstanceOf[Signature]
          val ok2 = secp256k1_ecdsa_signature_parse_compact(ctx, sig, ssig)
          if (ok2 == 0)
            Left(s"failed to parse signature ${bytearray2hex(signature)}")
          else {
            // check validity
            val valid = secp256k1_ecdsa_verify(ctx, sig, cmessage, pubkey)
            Right(valid == 1)
          }
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
      alloc[UByte](SERIALIZED_PUBKEY_SIZE).asInstanceOf[Ptr[UByte]]
    for (i <- 0 until value.size) !(spubkey + i) = value(i)

    val ctweak =
      alloc[UByte](TWEAK_SIZE).asInstanceOf[Ptr[UByte]]
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

  def add(pubkey: PublicKey): PublicKey = Zone { implicit z =>
    // load things in C format
    val spubkey1 =
      alloc[UByte](SERIALIZED_PUBKEY_SIZE).asInstanceOf[Ptr[UByte]]
    for (i <- 0 until value.size) !(spubkey1 + i) = value(i)

    val spubkey2 =
      alloc[UByte](SERIALIZED_PUBKEY_SIZE).asInstanceOf[Ptr[UByte]]
    for (i <- 0 until pubkey.value.size) !(spubkey2 + i) = pubkey.value(i)

    // parse pubkeys
    val pubkey1 =
      alloc[UByte](PUBKEY_SIZE).asInstanceOf[PubKey]
    secp256k1_ec_pubkey_parse(
      ctx,
      pubkey1,
      spubkey1,
      SERIALIZED_PUBKEY_SIZE
    )

    val pubkey2 =
      alloc[UByte](PUBKEY_SIZE).asInstanceOf[PubKey]
    secp256k1_ec_pubkey_parse(
      ctx,
      pubkey2,
      spubkey2,
      SERIALIZED_PUBKEY_SIZE
    )

    // build the array of pointers to the two keys
    val arr = alloc[PubKey](2)
    !(arr + 0) = pubkey1
    !(arr + 1) = pubkey2

    // do the combination
    val result = alloc[UByte](PUBKEY_SIZE).asInstanceOf[PubKey]
    secp256k1_ec_pubkey_combine(ctx, result, arr, 2.toULong)

    // serialize resulting public key
    val sizeptr = alloc[CSize](1)
    !sizeptr = SERIALIZED_PUBKEY_SIZE

    val sresult = alloc[UByte](SERIALIZED_PUBKEY_SIZE)
    secp256k1_ec_pubkey_serialize(
      ctx,
      sresult,
      sizeptr,
      result,
      EC_COMPRESSED
    )

    val spkey = ptr2bytearray(sresult, SERIALIZED_PUBKEY_SIZE.toInt)
    PublicKey(spkey)
  }

  def add(tweak: Array[UByte]): PublicKey = Zone { implicit z =>
    // load things in C format
    val spubkey =
      alloc[UByte](SERIALIZED_PUBKEY_SIZE).asInstanceOf[Ptr[UByte]]
    for (i <- 0 until value.size) !(spubkey + i) = value(i)

    val ctweak =
      alloc[UByte](TWEAK_SIZE).asInstanceOf[Ptr[UByte]]
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
      alloc[UByte](SERIALIZED_PUBKEY_SIZE).asInstanceOf[Ptr[UByte]]
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

  def toCompressed(): Array[UByte] =
    value // keys are always stored in compressed form

  def toUncompressed(): Array[UByte] = Zone { implicit z =>
    // load in C format
    val spubkey =
      alloc[UByte](SERIALIZED_PUBKEY_SIZE).asInstanceOf[Ptr[UByte]]
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

    // serialize public key as uncompressed
    val supubkey = alloc[UByte](SERIALIZED_UNCOMPRESSED_PUBKEY_SIZE)
      .asInstanceOf[Ptr[UByte]]

    val sizeptr = alloc[CSize](1)
    !sizeptr = SERIALIZED_UNCOMPRESSED_PUBKEY_SIZE

    secp256k1_ec_pubkey_serialize(
      ctx,
      supubkey,
      sizeptr,
      pubkey,
      EC_UNCOMPRESSED
    )

    ptr2bytearray(supubkey, SERIALIZED_UNCOMPRESSED_PUBKEY_SIZE.toInt)
  }
}
