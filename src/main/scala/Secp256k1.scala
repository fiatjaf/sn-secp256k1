import scala.scalanative.libc.stdlib
import scala.scalanative.libc.string
import scala.scalanative.unsafe._
import scala.scalanative.unsigned._
import javax.crypto.SecretKey

object Secp256k1 {
  import Secp256k1Extern._
  import Secp256k1Aux._

  // create context (keep it globally here for the life of this library)
  val ctx = secp256k1_context_create(CONTEXT_SIGN | CONTEXT_VERIFY)
  val randomize = stdlib.malloc(32L.toULong)
  fill_random(randomize, 32L.toULong)
  secp256k1_context_randomize(ctx, randomize)
  stdlib.free(randomize)

  def main(args: Array[String]): Unit = {
    println("hello")
    val k = Keys.createPrivateKey()
    println(k.privateKey.map(_.toHexString).mkString)
    val p = k.publicKey()
    println(p.publicKey.map(_.toHexString).mkString)
  }

  case class PrivateKey(privateKey: Array[UByte]) {
    def publicKey(): PublicKey = {
      // load private key into C form
      val seckey = stdlib.malloc(SECKEY_SIZE)
      for (i <- 0 until privateKey.size) !(seckey + i) = privateKey(i).toByte

      // create public key
      val pubkey = stdlib.malloc(PUBKEY_SIZE)
      secp256k1_ec_pubkey_create(ctx, pubkey, seckey)

      // serialize public key
      val spubkey = stdlib.malloc(SERIALIZED_PUBKEY_SIZE)
      secp256k1_ec_pubkey_serialize(
        ctx,
        spubkey,
        SERIALIZED_PUBKEY_SIZE,
        pubkey,
        EC_COMPRESSED
      )
      val spkey = Array.ofDim[UByte](SERIALIZED_PUBKEY_SIZE.toLong.toInt)
      for (i <- 0 until spkey.size) spkey(i) = (!(spubkey + i)).toUByte

      // cleanup everything
      stdlib.free(seckey)
      stdlib.free(pubkey)
      stdlib.free(spubkey)

      PublicKey(spkey)
    }

    // def sign(sighash: Array[UByte]): Array[UByte] = {}
  }

  case class PublicKey(publicKey: Array[UByte]) {
    // def verifySignature(): Array[UByte] = {}
  }

  object Keys {
    def createPrivateKey(): PrivateKey = {
      // create private key
      val seckey = stdlib.malloc(SECKEY_SIZE)
      val ok = fill_random(seckey, SECKEY_SIZE)
      if (ok == 0) {
        throw Exception("failed to gather randomness for secret key")
      }
      var validity = 0
      while (validity == 0) validity = secp256k1_ec_seckey_verify(ctx, seckey)

      // serialize private key
      val sskey = Array.ofDim[UByte](SECKEY_SIZE.toLong.toInt)
      for (i <- 0 until sskey.size) sskey(i) = (!(seckey + i)).toUByte
      stdlib.free(seckey)

      // return the keys object
      PrivateKey(sskey)
    }
  }
}

object Secp256k1Aux {
  type Context = Ptr[Byte]
  type KeyPair = Ptr[Byte] // 96 bytes
  type SecKey = Ptr[Byte] // 32 bytes
  type PubKey = Ptr[Byte] // 64 bytes
  type SerializedPubKey = Ptr[Byte] // 33 bytes
  type SigHash = Ptr[Byte] // 32 bytes
  type Signature = Ptr[Byte] // 64 bytes
  type SerializedSignature = Ptr[Byte] // 64 bytes

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
  val SERIALIZED_SIGNATURE_SIZE = 64L.toULong
}

@link("secp256k1")
@extern
object Secp256k1Extern {
  import Secp256k1Aux._

  def fill_random(data: Ptr[Byte], size: CSize): Int = extern
  def secp256k1_context_create(flags: UInt): Context = extern
  def secp256k1_context_randomize(ctx: Context, data: Ptr[Byte]): Int = extern
  def secp256k1_ec_seckey_verify(ctx: Context, seckey: SecKey): Int = extern
  def secp256k1_ec_pubkey_create(
      ctx: Context,
      pubkey: PubKey,
      seckey: SecKey
  ): Int = extern
  def secp256k1_ec_pubkey_serialize(
      ctx: Context,
      output: SerializedPubKey,
      outputlen: CSize,
      pubkey: PubKey,
      flags: UInt
  ): Int = extern
  def secp256k1_ecdsa_sign(
      ctx: Context,
      sig: SerializedSignature,
      sighash: SigHash,
      seckey: SecKey,
      nonce_function: Ptr[Byte],
      nonce_data: Ptr[Byte]
  ): Int = extern
  def secp256k1_ecdsa_signature_serialize_compact(
      ctx: Context,
      sig: Signature,
      serialized_signature: SerializedSignature
  ): Int = extern
  def secp256k1_ecdsa_signature_parse_compact(
      ctx: Context,
      sig: Signature,
      serialized_signature: SerializedSignature
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
