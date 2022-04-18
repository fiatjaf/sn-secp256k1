package secp256k1

import scala.scalanative.libc.stdlib
import scala.scalanative.libc.string
import scala.scalanative.unsafe._
import scala.scalanative.unsigned._

object Secp256k1 {
  import secp256k1.Secp256k1Aux._
  import secp256k1.Secp256k1Extern._
  import secp256k1.UtilsExtern._

  // create context (keep it globally here for the life of this library)
  val ctx = secp256k1_context_create(CONTEXT_SIGN | CONTEXT_VERIFY)
  val randomize = stdlib.malloc(32L.toULong).asInstanceOf[Ptr[UByte]]
  fill_random(randomize, 32L.toULong)
  secp256k1_context_randomize(ctx, randomize)
  stdlib.free(randomize.asInstanceOf[Ptr[Byte]])

  // helper functions
  //
  def bytearray2hex(arr: Array[UByte]): String =
    arr
      .map(_.toHexString)
      .map(x => if (x.size == 2) x else s"0$x")
      .mkString

  def ptr2hex(ptr: Ptr[UByte], size: Int): Unit =
    bytearray2hex(ptr2bytearray(ptr, size))

  def ptr2bytearray(ptr: Ptr[UByte], size: Int): Array[UByte] = {
    val bytearray = Array.ofDim[UByte](size)
    for (i <- 0 until size) bytearray(i) = (!(ptr + i)).toUByte
    bytearray
  }

  def hex2bytearray(hex: String): Array[UByte] =
    Array.tabulate[UByte](hex.size / 2)(i =>
      Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16).toUByte
    )
}

object Secp256k1Aux {
  type Context = Ptr[UByte]
  type KeyPair = Ptr[UByte] // 96 bytes
  type SecKey = Ptr[UByte] // 32 bytes
  type PubKey = Ptr[UByte] // 64 bytes
  type SerializedPubKey = Ptr[UByte] // 33 bytes
  type SigHash = Ptr[UByte] // 32 bytes
  type Signature = Ptr[UByte] // 64 bytes
  type SignatureCompactSerialized = Ptr[UByte] // 64 bytes

  private val FLAGS_TYPE_CONTEXT = (1 << 0).toUInt
  private val FLAGS_BIT_CONTEXT_VERIFY = (1 << 8).toUInt
  private val FLAGS_BIT_CONTEXT_SIGN = (1 << 9).toUInt
  private val FLAGS_TYPE_COMPRESSION = (1 << 1).toUInt
  private val FLAGS_BIT_COMPRESSION = (1 << 8).toUInt

  val CONTEXT_VERIFY = (FLAGS_TYPE_CONTEXT | FLAGS_BIT_CONTEXT_VERIFY)
  val CONTEXT_SIGN = (FLAGS_TYPE_CONTEXT | FLAGS_BIT_CONTEXT_SIGN)
  val EC_COMPRESSED = (FLAGS_TYPE_COMPRESSION | FLAGS_BIT_COMPRESSION)
  val EC_UNCOMPRESSED = (FLAGS_TYPE_COMPRESSION)

  val SECKEY_SIZE = 32L.toULong
  val PUBKEY_SIZE = 64L.toULong
  val SIGHASH_SIZE = 32L.toULong
  val SERIALIZED_PUBKEY_SIZE = 33L.toULong
  val SIGNATURE_SIZE = 64L.toULong
  val SIGNATURE_COMPACT_SERIALIZED_SIZE = 64L.toULong
}

@extern
object UtilsExtern {
  def fill_random(data: Ptr[UByte], size: CSize): Int = extern
}

@link("secp256k1")
@extern
object Secp256k1Extern {
  import Secp256k1Aux._

  def secp256k1_context_create(flags: UInt): Context = extern
  def secp256k1_context_randomize(ctx: Context, data: Ptr[UByte]): Int = extern
  def secp256k1_ec_seckey_verify(ctx: Context, seckey: SecKey): Int = extern
  def secp256k1_ec_pubkey_create(
      ctx: Context,
      pubkey: PubKey,
      seckey: SecKey
  ): Int = extern
  def secp256k1_ec_pubkey_serialize(
      ctx: Context,
      output: SerializedPubKey,
      outputlenbyteswritten: Ptr[CSize],
      pubkey: PubKey,
      flags: UInt
  ): Int = extern
  def secp256k1_ecdsa_sign(
      ctx: Context,
      sig: Signature,
      sighash: SigHash,
      seckey: SecKey,
      nonce_function: Ptr[Byte],
      nonce_data: Ptr[Byte]
  ): Int = extern
  def secp256k1_ecdsa_signature_serialize_der(
      ctx: Context,
      output: Ptr[UByte],
      outputlenbyteswritten: Ptr[CSize],
      sig: Signature
  ): Int = extern
  def secp256k1_ecdsa_signature_parse_der(
      ctx: Context,
      input: Ptr[UByte],
      inputlen: CSize,
      sig: Signature
  ): Int = extern
  def secp256k1_ecdsa_signature_serialize_compact(
      ctx: Context,
      serialized_signature: SignatureCompactSerialized,
      sig: Signature
  ): Int = extern
  def secp256k1_ecdsa_signature_parse_compact(
      ctx: Context,
      sig: Signature,
      serialized_signature: SignatureCompactSerialized
  ): Int = extern
  def secp256k1_ec_pubkey_parse(
      ctx: Context,
      pubkey: PubKey,
      input: SerializedPubKey,
      inputlen: CSize
  ): Int = extern
  def secp256k1_ecdsa_verify(
      ctx: Context,
      sig: Signature,
      sighash: SigHash,
      pubkey: PubKey
  ): Int = extern
}
